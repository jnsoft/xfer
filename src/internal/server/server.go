package server

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/jnsoft/xfer/src/internal/connection"
	"golang.org/x/term"
)

const (
	bufferSize              = 32 * 1024
	defaultHandshakeTimeout = 10 * time.Second
)

type Config struct {
	KeepListening    bool
	AllowMultiple    bool
	MaxClients       int
	Timeout          int
	Secure           bool
	UseTLS           bool
	Compress         bool
	Secret           string
	CertFile         string
	KeyFile          string
	HandshakeTimeout time.Duration
	tlsConfig        *tls.Config
	Input            io.Reader
	Output           io.Writer
	ErrorOutput      io.Writer
}

func RunServer(
	ctx context.Context,
	addr string,
	keep, allowMultiple bool,
	maxClients, timeout int,
	secure, useTLS, compress bool,
	secret, certFile, keyFile string,
) {
	listener, err := net.Listen("tcp", addr)
	if err != nil {
		fmt.Fprintf(os.Stderr, "listen error: %v\n", err)
		os.Exit(2)
	}
	defer listener.Close()

	output := io.Writer(os.Stdout)
	if term.IsTerminal(int(os.Stdout.Fd())) {
		output = newTerminalWriter(os.Stdout)
	}

	err = Serve(ctx, listener, Config{
		KeepListening:    keep,
		AllowMultiple:    allowMultiple,
		MaxClients:       maxClients,
		Timeout:          timeout,
		Secure:           secure,
		UseTLS:           useTLS,
		Compress:         compress,
		Secret:           secret,
		CertFile:         certFile,
		KeyFile:          keyFile,
		HandshakeTimeout: defaultHandshakeTimeout,
		Input:            os.Stdin,
		Output:           output,
		ErrorOutput:      os.Stderr,
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "server error: %v\n", err)
		os.Exit(2)
	}
}

func Serve(ctx context.Context, listener net.Listener, config Config) error {
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

	input := config.Input
	if input == nil {
		input = strings.NewReader("")
	}

	output := config.Output
	if output == nil {
		output = io.Discard
	}

	errorOutput := config.ErrorOutput
	if errorOutput == nil {
		errorOutput = io.Discard
	}

	if config.UseTLS {
		cert, err := tls.LoadX509KeyPair(config.CertFile, config.KeyFile)
		if err != nil {
			return fmt.Errorf("load TLS certificate and key: %w", err)
		}

		config.tlsConfig = &tls.Config{
			Certificates: []tls.Certificate{cert},
			MinVersion:   tls.VersionTLS13,
		}
	}

	fmt.Fprintf(errorOutput, "listening on %s\n", listener.Addr())

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
			byteCount, err := input.Read(buffer)
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
							fmt.Fprintf(errorOutput, "send error to %s: %v\n", clientConn.RemoteAddr(), writeErr)
						}
						_ = clientConn.Close()
					}
				}
			}

			if err == io.EOF {
				return
			}
			if err != nil {
				fmt.Fprintf(errorOutput, "stdin error: %v\n", err)
				return
			}
		}
	}()

	handleClient := func(conn net.Conn) {
		defer conn.Close()
		defer releaseClient()

		if err := connection.SendAdmission(conn, true); err != nil {
			fmt.Fprintf(errorOutput, "admission write error to %s: %v\n", conn.RemoteAddr(), err)
			return
		}

		useConn, err := prepareConnection(conn, config)
		if err != nil {
			fmt.Fprintf(errorOutput, "connection setup error from %s: %v\n", conn.RemoteAddr(), err)
			return
		}

		if err := connection.NegotiateCompression(useConn, true, config.Compress); err != nil {
			fmt.Fprintf(errorOutput, "compression setup error from %s: %v\n", conn.RemoteAddr(), err)
			return
		}

		if config.Compress {
			useConn = connection.WrapWithCompression(useConn)
		}

		clientsMu.Lock()
		clients[useConn] = struct{}{}
		clientsMu.Unlock()

		connection.HandleConn(useConn, output, errorOutput, config.Timeout)

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

		fmt.Fprintf(errorOutput, "connection attempt from %s\n", conn.RemoteAddr())

		if !tryReserveClient() {
			fmt.Fprintf(
				errorOutput,
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
		if config.tlsConfig == nil {
			return nil, errors.New("TLS configuration is not initialized")
		}

		tlsConn := tls.Server(conn, config.tlsConfig)

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
