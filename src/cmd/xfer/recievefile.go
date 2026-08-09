package main

import (
	"context"
	"crypto/tls"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/jnsoft/xfer/src/internal/server"
	"github.com/jnsoft/xfer/src/internal/tlsconfig"
)

func receiveFile(args []string) {
	options, positional, err := parseOptions(args)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
	if options.Help {
		usage()
		return
	}
	if len(positional) != 1 {
		fmt.Fprintln(os.Stderr, "Usage: xfer get [options] <destination-file>")
		os.Exit(2)
	}

	var tlsConfig *tls.Config
	if options.TLS {
		tlsConfig, err = tlsconfig.LoadServerTLSConfig(
			options.CertFile, options.KeyFile,
		)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(2)
		}
	}

	ctx, stop := signal.NotifyContext(
		context.Background(), syscall.SIGINT, syscall.SIGTERM,
	)
	defer stop()

	serverConfig := options.serverConfig()
	serverConfig.TLSConfig = tlsConfig
	serverConfig.ErrorOutput = os.Stderr

	err = server.ReceiveFile(ctx, server.FileConfig{
		Server:      serverConfig,
		Destination: positional[0],
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "receive failed: %v\n", err)
		os.Exit(2)
	}
}
