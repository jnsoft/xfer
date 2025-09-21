package client

import (
	"fmt"
	"io"
	"net"
	"os"
	"sync"

	"github.com/jnsoft/xfer/src/connection"
)

func RunClient(target string, timeout int, secure bool, key string) {
	conn, err := net.Dial("tcp", target)
	if err != nil {
		fmt.Fprintf(os.Stderr, "connect error: %v\n", err)
		os.Exit(2)
	}
	defer conn.Close()

	var useConn net.Conn = conn
	if secure {
		secureConn, err := connection.WrapWithAE(conn, false, key)
		if err != nil {
			fmt.Fprintf(os.Stderr, "handshake error: %v\n", err)
			os.Exit(2)
		}
		useConn = secureConn
		defer secureConn.Close()
	}

	connection.ApplyTimeout(conn, timeout)

	var wg sync.WaitGroup
	wg.Add(2)

	// stdin -> conn
	go func() {
		defer wg.Done()
		_, _ = io.Copy(conn, os.Stdin)
		// when stdin EOF, close write side if possible
		if cw, ok := useConn.(interface{ CloseWrite() error }); ok {
			_ = cw.CloseWrite()
		}
	}()

	// conn -> stdout
	go func() {
		defer wg.Done()
		_, _ = io.Copy(os.Stdout, conn)
	}()

	wg.Wait()
}
