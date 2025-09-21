package server

import (
	"crypto/tls"
	"fmt"
	"net"
	"os"

	"github.com/jnsoft/xfer/src/connection"
)

func RunServer(addr string, keep bool, timeout int, secure, use_tls bool, secret, certFile, keyFile string) {
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		fmt.Fprintf(os.Stderr, "listen error: %v\n", err)
		os.Exit(2)
	}
	defer ln.Close()
	fmt.Fprintf(os.Stderr, "listening on %s\n", addr)

	for {
		conn, err := ln.Accept()
		if err != nil {
			fmt.Fprintf(os.Stderr, "accept error: %v\n", err)
			if keep {
				continue
			}
			break
		}
		fmt.Fprintf(os.Stderr, "connection from %s\n", conn.RemoteAddr())

		var useConn net.Conn = conn
		if use_tls {
			// Load server certificate and key from files
			cert, err := tls.LoadX509KeyPair(certFile, keyFile)
			if err != nil {
				fmt.Fprintf(os.Stderr, "TLS cert/key load error: %v\n", err)
				_ = conn.Close()
				continue
			}
			tlsConf := &tls.Config{
				Certificates: []tls.Certificate{cert},
				MinVersion:   tls.VersionTLS13,
			}
			tlsConn := tls.Server(conn, tlsConf)
			if err := tlsConn.Handshake(); err != nil {
				fmt.Fprintf(os.Stderr, "TLS handshake error: %v\n", err)
				_ = conn.Close()
				continue
			}
			useConn = tlsConn
		} else if secure {
			secureConn, err := connection.WrapWithAE(conn, true, secret)
			if err != nil {
				fmt.Fprintf(os.Stderr, "handshake error: %v\n", err)
				_ = conn.Close()
				if keep {
					continue
				}
				break
			}
			useConn = secureConn
		}

		connection.HandleConn(useConn, timeout)

		if !keep {
			break
		}
	}
}
