package main

import (
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"
)

var (
	flagListen  = flag.Bool("l", false, "listen mode (server)")
	flagPort    = flag.Int("p", 9999, "port to listen on or connect to")
	flagKeep    = flag.Bool("k", false, "keep listening after a connection closes (server)")
	flagTimeout = flag.Int("t", 0, "I/O timeout seconds (0 = no timeout)")
	flagHelp    = flag.Bool("h", false, "show help")
)

func usage() {
	fmt.Fprintf(os.Stderr, "Usage:\n")
	fmt.Fprintf(os.Stderr, "  Connect mode: %s [host:port]\n", os.Args[0])
	fmt.Fprintf(os.Stderr, "  Listen mode:  %s -l [-p port] [-k]\n", os.Args[0])
	flag.PrintDefaults()
}

func main() {
	flag.Parse()
	if *flagHelp {
		usage()
		return
	}

	// setup interrupt handling so we close cleanly
	sigc := make(chan os.Signal, 1)
	signal.Notify(sigc, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigc
		os.Exit(0)
	}()

	if *flagListen {
		addr := fmt.Sprintf(":%d", *flagPort)
		runServer(addr)
		return
	}

	// client mode: need host:port argument
	target := ""
	if flag.NArg() > 0 {
		target = flag.Arg(0)
	} else {
		// if no host:port provided, use localhost:port
		target = fmt.Sprintf("127.0.0.1:%d", *flagPort)
	}

	runClient(target)
}

func applyTimeout(c net.Conn) {
	if *flagTimeout <= 0 {
		return
	}
	d := time.Duration(*flagTimeout) * time.Second
	_ = c.SetDeadline(time.Now().Add(d))
}

func runClient(target string) {
	conn, err := net.Dial("tcp", target)
	if err != nil {
		fmt.Fprintf(os.Stderr, "connect error: %v\n", err)
		os.Exit(2)
	}
	defer conn.Close()

	applyTimeout(conn)

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

func runServer(addr string) {
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
			if *flagKeep {
				continue
			}
			break
		}
		fmt.Fprintf(os.Stderr, "connection from %s\n", conn.RemoteAddr())

		handleConn(conn)

		if !*flagKeep {
			break
		}
	}
}

func handleConn(conn net.Conn) {
	defer conn.Close()
	applyTimeout(conn)

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
