package main

import (
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/jnsoft/xfer/src/client"
	"github.com/jnsoft/xfer/src/server"
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
		server.RunServer(addr, *flagKeep, *flagTimeout)
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

	client.RunClient(target, *flagTimeout)
}
