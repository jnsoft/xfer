package connection

import (
	"errors"
	"fmt"
	"io"
	"net"
	"time"
)


func HandleConn(conn net.Conn, output, errorOutput io.Writer, timeout time.Duration) {
	defer conn.Close()
	ApplyTimeout(conn, timeout)

	if _, err := io.Copy(output, conn); err != nil &&
		!errors.Is(err, io.EOF) &&
		!errors.Is(err, net.ErrClosed) {
		fmt.Fprintf(errorOutput, "receive error from %s: %v\n", conn.RemoteAddr(), err)
	}

	fmt.Fprintf(errorOutput, "connection closed %s\n", conn.RemoteAddr())
}

func ApplyTimeout(conn net.Conn, timeout time.Duration) {
    if timeout <= 0 {
        return
    }
    _ = conn.SetDeadline(time.Now().Add(timeout))
}
