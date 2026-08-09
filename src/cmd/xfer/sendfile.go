package main

import (
	"crypto/tls"
	"fmt"
	"os"

	"github.com/jnsoft/xfer/src/internal/client"
	"github.com/jnsoft/xfer/src/internal/tlsconfig"
)

func sendFile(args []string) {
	options, positional, err := parseOptions(args)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
	if options.Help {
		usage()
		return
	}
	if len(positional) < 1 || len(positional) > 2 {
		fmt.Fprintln(os.Stderr, "Usage: xfer send [options] <source-file> [host:port]")
		os.Exit(2)
	}

	sourcePath := positional[0]
	target, err := options.target(positional[1:])
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}

	var tlsConfig *tls.Config
	if options.TLS {
		tlsConfig, err = tlsconfig.LoadClientTLSConfig(options.CertFile, target)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(2)
		}
	}

	connectionConfig := options.clientConfig(target)
	connectionConfig.TLSConfig = tlsConfig

	if err := client.SendFile(client.FileConfig{
		Connection: connectionConfig,
		SourcePath: sourcePath,
	}); err != nil {
		fmt.Fprintf(os.Stderr, "send failed: %v\n", err)
		os.Exit(2)
	}
}
