package client

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"sync"

	"github.com/jnsoft/xfer/src/internal/connection"
)

func RunClient(target string, timeout int, secure, use_tls bool, secret, certFile string) {
	conn, err := net.Dial("tcp", target)
	if err != nil {
		fmt.Fprintf(os.Stderr, "connect error: %v\n", err)
		os.Exit(2)
	}
	defer conn.Close()

	var useConn net.Conn = conn
	if use_tls {
		tlsConf := &tls.Config{
			MinVersion:         tls.VersionTLS13,
			InsecureSkipVerify: true, // WARNING: for demo only!
		}
		if certFile != "" {
			caCert, err := os.ReadFile(certFile)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Failed to read cert file: %v\n", err)
				os.Exit(2)
			}
			caPool := x509.NewCertPool()
			if !caPool.AppendCertsFromPEM(caCert) {
				fmt.Fprintf(os.Stderr, "Failed to parse cert file\n")
				os.Exit(2)
			}
			tlsConf.RootCAs = caPool
		}
		tlsConn := tls.Client(conn, tlsConf)
		if err := tlsConn.Handshake(); err != nil {
			fmt.Fprintf(os.Stderr, "TLS handshake error: %v\n", err)
			os.Exit(2)
		}
		useConn = tlsConn
		defer tlsConn.Close()
	} else if secure {
		secureConn, err := connection.WrapWithAE(conn, false, secret)
		if err != nil {
			fmt.Fprintf(os.Stderr, "handshake error: %v\n", err)
			os.Exit(2)
		}
		useConn = secureConn
		defer secureConn.Close()
	}

	connection.ApplyTimeout(useConn, timeout)

	var wg sync.WaitGroup
	wg.Add(2)

	// stdin -> conn
	go func() {
		defer wg.Done()

		if _, err := io.Copy(useConn, os.Stdin); err != nil && !errors.Is(err, net.ErrClosed) {
			fmt.Fprintf(os.Stderr, "send error: %v\n", err)
			_ = useConn.Close()
			return
		}

		// A normal stdin EOF only closes this direction; replies can still arrive.
		if cw, ok := useConn.(interface{ CloseWrite() error }); ok {
			_ = cw.CloseWrite()
		}
	}()

	// conn -> stdout
	go func() {
		defer wg.Done()

		if _, err := io.Copy(os.Stdout, useConn); err != nil && !errors.Is(err, net.ErrClosed) {
			fmt.Fprintf(os.Stderr, "receive error: %v\n", err)
		} else {
			fmt.Fprintln(os.Stderr, "server closed connection")
		}
		os.Exit(0)
	}()

	wg.Wait()
}
