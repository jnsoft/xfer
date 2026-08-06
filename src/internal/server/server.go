package server

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"time"

	"github.com/jnsoft/xfer/src/internal/connection"
)

const (
	bufferSize              = 32 * 1024
	defaultHandshakeTimeout = 10 * time.Second
)

type Config struct {
	Addr             string
	KeepListening    bool
	AllowMultiple    bool
	MaxClients       int
	Timeout          time.Duration
	Secure           bool
	UseTLS           bool
	Compress         bool
	Secret           string
	HandshakeTimeout time.Duration
	TLSConfig        *tls.Config
	Input            io.Reader
	Output           io.Writer
	ErrorOutput      io.Writer
}

func Run(ctx context.Context, config Config) error {
	if config.Input == nil {
		return errors.New("server input is required")
	}
	if config.Output == nil {
		return errors.New("server output is required")
	}
	if config.ErrorOutput == nil {
		return errors.New("server error output is required")
	}

	listener, err := net.Listen("tcp", config.Addr)
	if err != nil {
		return fmt.Errorf("listen: %w", err)
	}
	defer listener.Close()

	return Serve(ctx, listener, config)
}

func Serve(ctx context.Context, listener net.Listener, config Config) error {
	if config.Input == nil {
		return errors.New("server input is required")
	}
	if config.Output == nil {
		return errors.New("server output is required")
	}
	if config.ErrorOutput == nil {
		return errors.New("server error output is required")
	}

	if ctx == nil {
		ctx = context.Background()
	}
	serveCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	maxClients := config.MaxClients
	if maxClients <= 0 {
		maxClients = 1024
	}
	if !config.AllowMultiple {
		maxClients = 1
	}

	if config.UseTLS && config.TLSConfig == nil {
		return errors.New("TLS configuration is required")
	}

	fmt.Fprintf(config.ErrorOutput, "listening on %s\n", listener.Addr())

	var clientsMu sync.RWMutex
	clients := make(map[net.Conn]struct{})

	var clientsWG sync.WaitGroup

	closeClients := func() {
		clientsMu.RLock()
		currentClients := make([]net.Conn, 0, len(clients))
		for clientConn := range clients {
			currentClients = append(currentClients, clientConn)
		}
		clientsMu.RUnlock()

		for _, clientConn := range currentClients {
			_ = clientConn.Close()
		}
	}

	go func() {
		<-serveCtx.Done()
		_ = listener.Close()
	}()

	go func() {
		<-serveCtx.Done()
		closeClients()
	}()

	var clientsCountMu sync.Mutex
	connectedClients := 0

	tryReserveClient := func() bool {
		clientsCountMu.Lock()
		defer clientsCountMu.Unlock()

		if connectedClients >= maxClients {
			return false
		}

		connectedClients++
		return true
	}

	releaseClient := func() {
		clientsCountMu.Lock()
		connectedClients--
		clientsCountMu.Unlock()
	}

	// Only this goroutine reads server input. It broadcasts complete lines to
	// all currently connected clients.
	go func() {
		buffer := make([]byte, bufferSize)

		for {
			byteCount, err := config.Input.Read(buffer)
			if byteCount > 0 {
				clientsMu.RLock()
				currentClients := make([]net.Conn, 0, len(clients))
				for clientConn := range clients {
					currentClients = append(currentClients, clientConn)
				}
				clientsMu.RUnlock()

				for _, clientConn := range currentClients {
					if _, writeErr := clientConn.Write(buffer[:byteCount]); writeErr != nil {
						if !errors.Is(writeErr, net.ErrClosed) {
							fmt.Fprintf(config.ErrorOutput, "send error to %s: %v\n", clientConn.RemoteAddr(), writeErr)
						}
						_ = clientConn.Close()
					}
				}
			}

			if err == io.EOF {
				return
			}
			if err != nil {
				fmt.Fprintf(config.ErrorOutput, "stdin error: %v\n", err)
				return
			}
		}
	}()

	handleClient := func(conn net.Conn) {
		defer conn.Close()
		defer releaseClient()

		if err := connection.SendAdmission(conn, true); err != nil {
			fmt.Fprintf(config.ErrorOutput, "admission write error to %s: %v\n", conn.RemoteAddr(), err)
			return
		}

		useConn, err := prepareConnection(conn, config)
		if err != nil {
			fmt.Fprintf(config.ErrorOutput, "connection setup error from %s: %v\n", conn.RemoteAddr(), err)
			return
		}

		if err := connection.NegotiateCompression(useConn, true, config.Compress); err != nil {
			fmt.Fprintf(config.ErrorOutput, "compression setup error from %s: %v\n", conn.RemoteAddr(), err)
			return
		}

		if config.Compress {
			useConn = connection.WrapWithCompression(useConn)
		}

		clientsMu.Lock()
		clients[useConn] = struct{}{}
		clientsMu.Unlock()

		connection.HandleConn(useConn, config.Output, config.ErrorOutput, config.Timeout)

		clientsMu.Lock()
		delete(clients, useConn)
		clientsMu.Unlock()
	}

	for {
		conn, err := listener.Accept()
		if err != nil {
			if errors.Is(err, net.ErrClosed) || ctx.Err() != nil {
				clientsWG.Wait()
				return nil
			}
			return err
		}

		fmt.Fprintf(config.ErrorOutput, "connection attempt from %s\n", conn.RemoteAddr())

		if !tryReserveClient() {
			fmt.Fprintf(
				config.ErrorOutput,
				"connection rejected from %s: server is full (maximum %d clients)\n",
				conn.RemoteAddr(),
				maxClients,
			)
			_ = connection.SendAdmission(conn, false)
			_ = conn.Close()
			continue
		}

		if config.AllowMultiple || config.KeepListening {
			clientsWG.Add(1)
			go func() {
				defer clientsWG.Done()
				handleClient(conn)
			}()
			continue
		}

		handleClient(conn)
		return nil
	}
}

func prepareConnection(conn net.Conn, config Config) (net.Conn, error) {
	if config.UseTLS || config.Secure {
		handshakeTimeout := config.HandshakeTimeout
		if handshakeTimeout <= 0 {
			handshakeTimeout = defaultHandshakeTimeout
		}

		if err := conn.SetDeadline(time.Now().Add(handshakeTimeout)); err != nil {
			return nil, fmt.Errorf("set handshake deadline: %w", err)
		}
		defer conn.SetDeadline(time.Time{})
	}

	if config.UseTLS {
		tlsConn := tls.Server(conn, config.TLSConfig)
		if err := tlsConn.Handshake(); err != nil {
			return nil, fmt.Errorf("TLS handshake: %w", err)
		}
		return tlsConn, nil
	}

	if config.Secure {
		secureConn, err := connection.WrapWithAE(conn, true, config.Secret)
		if err != nil {
			return nil, fmt.Errorf("secure handshake: %w", err)
		}
		return secureConn, nil
	}

	return conn, nil
}
