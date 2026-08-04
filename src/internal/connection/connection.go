package connection

import (
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"time"
)

func HandleConn(conn net.Conn, timeout int) {
	defer conn.Close()
	ApplyTimeout(conn, timeout)

	if _, err := io.Copy(os.Stdout, conn); err != nil &&
		!errors.Is(err, io.EOF) &&
		!errors.Is(err, net.ErrClosed) {
		fmt.Fprintf(os.Stderr, "receive error from %s: %v\n", conn.RemoteAddr(), err)
	}

	fmt.Fprintf(os.Stderr, "connection closed %s\n", conn.RemoteAddr())
}

func ApplyTimeout(conn net.Conn, timeout int) {
	if timeout <= 0 {
		return
	}

	deadline := time.Now().Add(time.Duration(timeout) * time.Second)
	_ = conn.SetDeadline(deadline)
}
