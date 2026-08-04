package server

import (
	"bufio"
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
)

const (
	maxInputLine            = 1024 * 1024
	defaultHandshakeTimeout = 10 * time.Second
)

type Config struct {
	KeepListening    bool
	AllowMultiple    bool
	MaxClients       int
	Timeout          int
	Secure           bool
	UseTLS           bool
	Secret           string
	CertFile         string
	KeyFile          string
	HandshakeTimeout time.Duration
	Input            io.Reader
	Output           io.Writer
	ErrorOutput      io.Writer
}

func RunServer(
	addr string,
	keep, allowMultiple bool,
	maxClients, timeout int,
	secure, useTLS bool,
	secret, certFile, keyFile string,
) {
	listener, err := net.Listen("tcp", addr)
	if err != nil {
		fmt.Fprintf(os.Stderr, "listen error: %v\n", err)
		os.Exit(2)
	}
	defer listener.Close()

	err = Serve(listener, Config{
		KeepListening:    keep,
		AllowMultiple:    allowMultiple,
		MaxClients:       maxClients,
		Timeout:          timeout,
		Secure:           secure,
		UseTLS:           useTLS,
		Secret:           secret,
		CertFile:         certFile,
		KeyFile:          keyFile,
		HandshakeTimeout: defaultHandshakeTimeout,
		Input:            os.Stdin,
		Output:           os.Stdout,
		ErrorOutput:      os.Stderr,
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "server error: %v\n", err)
		os.Exit(2)
	}
}

func Serve(listener net.Listener, config Config) error {

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

	fmt.Fprintf(errorOutput, "listening on %s\n", listener.Addr())

	var clientsMu sync.RWMutex
	clients := make(map[net.Conn]struct{})

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
		scanner := bufio.NewScanner(input)
		scanner.Buffer(make([]byte, 64*1024), maxInputLine)

		for scanner.Scan() {
			line := scanner.Text()

			clientsMu.RLock()
			currentClients := make([]net.Conn, 0, len(clients))
			for clientConn := range clients {
				currentClients = append(currentClients, clientConn)
			}
			clientsMu.RUnlock()

			if len(currentClients) == 0 {
				fmt.Fprintln(errorOutput, "no clients connected")
				continue
			}

			for _, clientConn := range currentClients {
				if _, err := fmt.Fprintln(clientConn, line); err != nil {
					if !errors.Is(err, net.ErrClosed) {
						fmt.Fprintf(errorOutput, "send error to %s: %v\n", clientConn.RemoteAddr(), err)
					}
					_ = clientConn.Close()
				}
			}
		}

		if err := scanner.Err(); err != nil {
			fmt.Fprintf(errorOutput, "stdin error: %v\n", err)
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

		clientsMu.Lock()
		clients[useConn] = struct{}{}
		clientsMu.Unlock()

		connection.HandleConn(useConn, output, config.Timeout)

		clientsMu.Lock()
		delete(clients, useConn)
		clientsMu.Unlock()
	}

	for {
		conn, err := listener.Accept()
		if err != nil {
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
			go handleClient(conn)
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
		cert, err := tls.LoadX509KeyPair(config.CertFile, config.KeyFile)
		if err != nil {
			return nil, fmt.Errorf("load TLS certificate and key: %w", err)
		}

		tlsConn := tls.Server(conn, &tls.Config{
			Certificates: []tls.Certificate{cert},
			MinVersion:   tls.VersionTLS13,
		})

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
