package server

import (
	"fmt"
	"io"
	"net"
	"os"
	"sync"
	"time"
)

func RunServer(addr string, keep bool, timeout int) {
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

		handleConn(conn, timeout)

		if !keep {
			break
		}
	}
}

func handleConn(conn net.Conn, timeout int) {
	defer conn.Close()
	applyTimeout(conn, timeout)

	// copy conn -> stdout and stdin -> conn
	var wg sync.WaitGroup
	wg.Add(2)

	go func() {
		defer wg.Done()
		_, _ = io.Copy(os.Stdout, conn)
	}()

	go func() {
		defer wg.Done()
		_, _ = io.Copy(conn, os.Stdin)
		// when stdin EOF, close write side of connection
		if tcp, ok := conn.(*net.TCPConn); ok {
			_ = tcp.CloseWrite()
		}
	}()

	wg.Wait()
	fmt.Fprintf(os.Stderr, "connection closed %s\n", conn.RemoteAddr())
}

func applyTimeout(c net.Conn, timeout int) {
	if timeout <= 0 {
		return
	}
	d := time.Duration(timeout) * time.Second
	_ = c.SetDeadline(time.Now().Add(d))
}
