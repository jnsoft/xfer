package connection

import (
	"errors"
	"fmt"
	"io"
	"net"
	"time"
)

// connection.HandleConn(useConn, serverOutput, timeout)
func HandleConn(conn net.Conn, output io.Writer, timeout int) {
	defer conn.Close()
	ApplyTimeout(conn, timeout)

	if _, err := io.Copy(output, conn); err != nil &&
		!errors.Is(err, io.EOF) &&
		!errors.Is(err, net.ErrClosed) {
		fmt.Fprintf(output, "receive error from %s: %v\n", conn.RemoteAddr(), err)
	}

	fmt.Fprintf(output, "connection closed %s\n", conn.RemoteAddr())
}

func ApplyTimeout(conn net.Conn, timeout int) {
	if timeout <= 0 {
		return
	}

	deadline := time.Now().Add(time.Duration(timeout) * time.Second)
	_ = conn.SetDeadline(deadline)
}
