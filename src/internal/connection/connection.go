package connection

import (
	"errors"
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

		if _, err := io.Copy(os.Stdout, conn); err != nil && !errors.Is(err, net.ErrClosed) {
			fmt.Fprintf(os.Stderr, "receive error: %v\n", err)
		} else {
			fmt.Fprintf(os.Stderr, "peer closed connection %s\n", conn.RemoteAddr())
		}

		// Unblocks the stdin -> conn goroutine so HandleConn can return.
		_ = conn.Close()
	}()

	go func() {
		defer wg.Done()

		if _, err := io.Copy(conn, os.Stdin); err != nil && !errors.Is(err, net.ErrClosed) {
			fmt.Fprintf(os.Stderr, "send error: %v\n", err)
			_ = conn.Close()
			return
		}

		// Keep the read side available when local stdin reaches EOF normally.
		if cw, ok := conn.(interface{ CloseWrite() error }); ok {
			_ = cw.CloseWrite()
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
