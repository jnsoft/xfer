package server

import (
	"bufio"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"os"
	"sync"

	"github.com/jnsoft/xfer/src/internal/connection"
)

func RunServer(addr string, keep, allowMultiple bool, timeout int, secure, useTLS bool, secret, certFile, keyFile string) {
	listener, err := net.Listen("tcp", addr)
	if err != nil {
		fmt.Fprintf(os.Stderr, "listen error: %v\n", err)
		os.Exit(2)
	}
	defer listener.Close()

	fmt.Fprintf(os.Stderr, "listening on %s\n", addr)

	var clientsMu sync.RWMutex
	clients := make(map[net.Conn]struct{})

	var activeMu sync.Mutex
	activeClient := false

	go func() {
		scanner := bufio.NewScanner(os.Stdin)

		for scanner.Scan() {
			line := scanner.Text()

			clientsMu.RLock()
			currentClients := make([]net.Conn, 0, len(clients))
			for clientConn := range clients {
				currentClients = append(currentClients, clientConn)
			}
			clientsMu.RUnlock()

			if len(currentClients) == 0 {
				fmt.Fprintln(os.Stderr, "no clients connected")
				continue
			}

			for _, clientConn := range currentClients {
				if _, err := fmt.Fprintln(clientConn, line); err != nil {
					if !errors.Is(err, net.ErrClosed) {
						fmt.Fprintf(os.Stderr, "send error to %s: %v\n", clientConn.RemoteAddr(), err)
					}
					_ = clientConn.Close()
				}
			}
		}

		if err := scanner.Err(); err != nil {
			fmt.Fprintf(os.Stderr, "stdin error: %v\n", err)
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
			fmt.Fprintf(os.Stderr, "admission write error to %s: %v\n", conn.RemoteAddr(), err)
			return
		}

		var useConn net.Conn = conn

		if useTLS {
			cert, err := tls.LoadX509KeyPair(certFile, keyFile)
			if err != nil {
				fmt.Fprintf(os.Stderr, "TLS cert/key load error: %v\n", err)
				return
			}

			tlsConn := tls.Server(conn, &tls.Config{
				Certificates: []tls.Certificate{cert},
				MinVersion:   tls.VersionTLS13,
			})

			if err := tlsConn.Handshake(); err != nil {
				fmt.Fprintf(os.Stderr, "TLS handshake error from %s: %v\n", conn.RemoteAddr(), err)
				return
			}

			useConn = tlsConn
		} else if secure {
			secureConn, err := connection.WrapWithAE(conn, true, secret)
			if err != nil {
				fmt.Fprintf(os.Stderr, "handshake error from %s: %v\n", conn.RemoteAddr(), err)
				return
			}

			useConn = secureConn
		}

		clientsMu.Lock()
		clients[useConn] = struct{}{}
		clientsMu.Unlock()

		connection.HandleConn(useConn, timeout)

		clientsMu.Lock()
		delete(clients, useConn)
		clientsMu.Unlock()
	}

	for {
		conn, err := listener.Accept()
		if err != nil {
			fmt.Fprintf(os.Stderr, "accept error: %v\n", err)
			if keep || allowMultiple {
				continue
			}
			return
		}

		fmt.Fprintf(os.Stderr, "connection attempt from %s\n", conn.RemoteAddr())

		if allowMultiple {
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
			fmt.Fprintf(os.Stderr, "connection rejected from %s: server already has an active client\n", conn.RemoteAddr())
			_ = connection.SendAdmission(conn, false)
			_ = conn.Close()
			continue
		}

		if keep {
			go handleClient(conn, true)
			continue
		}

		// Without -k, serve the first client and exit when it disconnects.
		handleClient(conn, true)
		return
	}
}
