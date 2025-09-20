package server

import (
	"fmt"
	"net"
	"os"

	"github.com/jnsoft/xfer/src/connection"
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

		connection.HandleConn(conn, timeout)

		if !keep {
			break
		}
	}
}
