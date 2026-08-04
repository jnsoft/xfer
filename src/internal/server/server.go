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

	"github.com/jnsoft/xfer/src/internal/connection"
)

type Config struct {
	KeepListening bool
	AllowMultiple bool
	Timeout       int
	Secure        bool
	UseTLS        bool
	Secret        string
	CertFile      string
	KeyFile       string
	Input         io.Reader
	Output        io.Writer
	ErrorOutput   io.Writer
}

func RunServer(addr string, keep, allowMultiple bool, timeout int, secure, useTLS bool, secret, certFile, keyFile string) {
	listener, err := net.Listen("tcp", addr)
	if err != nil {
		fmt.Fprintf(os.Stderr, "listen error: %v\n", err)
		os.Exit(2)
	}

	err = Serve(listener, Config{
		KeepListening: keep,
		AllowMultiple: allowMultiple,
		Timeout:       timeout,
		Secure:        secure,
		UseTLS:        useTLS,
		Secret:        secret,
		CertFile:      certFile,
		KeyFile:       keyFile,
		Input:         os.Stdin,
		Output:        os.Stdout,
		ErrorOutput:   os.Stderr,
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "server error: %v\n", err)
		os.Exit(2)
	}
}

func Serve(listener net.Listener, config Config) error {
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

	var activeMu sync.Mutex
	activeClient := false

	// Only this goroutine reads server input. It broadcasts complete lines to
	// all currently connected clients.
	go func() {
		scanner := bufio.NewScanner(input)
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

	handleClient := func(conn net.Conn, singleClient bool) {
		defer conn.Close()

		if singleClient {
			defer func() {
				activeMu.Lock()
				activeClient = false
				activeMu.Unlock()
			}()
		}

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

		if config.AllowMultiple {
			go handleClient(conn, false)
			continue
		}

		activeMu.Lock()
		busy := activeClient
		if !busy {
			activeClient = true
		}
		activeMu.Unlock()

		if busy {
			fmt.Fprintf(errorOutput, "connection rejected from %s: server already has an active client\n", conn.RemoteAddr())
			_ = connection.SendAdmission(conn, false)
			_ = conn.Close()
			continue
		}

		if config.KeepListening {
			go handleClient(conn, true)
			continue
		}

		handleClient(conn, true)
		return nil
	}
}

func prepareConnection(conn net.Conn, config Config) (net.Conn, error) {
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
