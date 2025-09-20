package client

import (
	"fmt"
	"io"
	"net"
	"os"
	"sync"

	"github.com/jnsoft/xfer/src/connection"
)

func RunClient(target string, timeout int) {
	conn, err := net.Dial("tcp", target)
	if err != nil {
		fmt.Fprintf(os.Stderr, "connect error: %v\n", err)
		os.Exit(2)
	}
	defer conn.Close()

	connection.ApplyTimeout(conn, timeout)

	var wg sync.WaitGroup
	wg.Add(2)

	// stdin -> conn
	go func() {
		defer wg.Done()
		_, _ = io.Copy(conn, os.Stdin)
		// when stdin EOF, close write side if possible
		if tcp, ok := conn.(*net.TCPConn); ok {
			_ = tcp.CloseWrite()
		}
	}()

	// conn -> stdout
	go func() {
		defer wg.Done()
		_, _ = io.Copy(os.Stdout, conn)
	}()

	wg.Wait()
}
