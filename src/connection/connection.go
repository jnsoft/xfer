package connection

import (
	"fmt"
	"io"
	"net"
	"os"
	"sync"
	"time"
)

func HandleConn(conn net.Conn, timeout int) {
	defer conn.Close()
	ApplyTimeout(conn, timeout)

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

func ApplyTimeout(c net.Conn, timeout int) {
	if timeout <= 0 {
		return
	}
	d := time.Duration(timeout) * time.Second
	_ = c.SetDeadline(time.Now().Add(d))
}
