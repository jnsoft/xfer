package main

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/jnsoft/xfer/src/internal/client"
	"github.com/jnsoft/xfer/src/internal/server"
	"github.com/jnsoft/xfer/src/internal/terminal"
	"github.com/jnsoft/xfer/src/internal/tlsconfig"
	"golang.org/x/term"
)

func main() {
	if len(os.Args) > 1 {
		switch os.Args[1] {
		case "send":
			sendFile(os.Args[2:])
			return
		case "get":
			receiveFile(os.Args[2:])
			return
		default:
			runInteractive(os.Args[1:])
		}
	}
}

func runInteractive(args []string) {
	options, positional, err := parseOptions(args)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}

	if options.Help {
		usage()
		return
	}

	if options.Listen {
		if len(positional) != 0 {
			fmt.Fprintln(os.Stderr, "Usage: xfer -l [options]")
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
			context.Background(),
			syscall.SIGINT,
			syscall.SIGTERM,
		)
		defer stop()

		serverOutput := io.Writer(os.Stdout)

		if term.IsTerminal(int(os.Stdout.Fd())) {
			serverOutput = terminal.NewWriter(os.Stdout)
		}

		serverConfig := options.serverConfig()
		serverConfig.TLSConfig = tlsConfig
		serverConfig.Input = os.Stdin
		serverConfig.Output = serverOutput
		serverConfig.ErrorOutput = os.Stderr

		if err := server.Run(ctx, serverConfig); err != nil {
			fmt.Fprintf(os.Stderr, "server error: %v\n", err)
			os.Exit(2)
		}
		return
	}

	target, err := options.target(positional)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}

	if options.ZeroIO {
		if len(positional) != 1 {
			fmt.Fprintln(os.Stderr, "Usage: xfer -z [options] <host:port>")
			os.Exit(2)
		}
		testConnection(positional[0], options.Timeout)
		return
	}

	var tlsConfig *tls.Config
	if options.TLS {
		tlsConfig, err = tlsconfig.LoadClientTLSConfig(options.CertFile, target)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(2)
		}
	}

	config := options.clientConfig(target)
	config.TLSConfig = tlsConfig
	config.Input = os.Stdin
	config.Output = os.Stdout
	config.ErrorOutput = os.Stderr

	if err := client.RunClient(config); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
}

func testConnection(target string, timeout time.Duration) {
	if timeout == 0 {
		timeout = 5 * time.Second
	}

	if err := client.CheckPort(target, timeout); err != nil {
		fmt.Fprintf(os.Stderr, "%s: connection failed: %v\n", target, err)
		os.Exit(1)
	}

	fmt.Fprintf(os.Stderr, "%s: connection succeeded\n", target)
}

func usage() {
	fmt.Fprintf(os.Stderr, `Usage:
  %s [options] [host:port]
  %s send [options] <source-file> <host:port>
  %s get [options] <destination-file>
  %s -l [options]

Modes:
  Client mode (default)
      Connect to host:port. If omitted, connects to 127.0.0.1:<port>.

  Server mode (-l)
      Listen on all interfaces at the selected port.

Server connection policy:
  -l              Serve one client, then exit after that client disconnects.
  -l -k           Keep listening. Permit one active client; reject additional
                  clients with "server is already connected".
  -l -m           Keep listening and permit up to 1024 simultaneous clients.
                  Lines entered at the server terminal are broadcast to every
                  connected client.
  -l -k -m        Equivalent to -l -m; -m already keeps the server listening.

Transport:
  -s=true         Use the custom ECDH P-256 and AES-256-GCM transport.
                  This is the default.
  -s=false        Use plaintext TCP. Do not use over an untrusted network.
  -a secret       Authenticate the custom secure handshake with a pre-shared
                  secret. Use the same secret on client and server to prevent
                  man-in-the-middle attacks. Ignored with -tls.
  -tls            Use TLS 1.3 instead of the custom secure transport.
  -cert file      Server: PEM certificate file. Required with -tls.
                  Client: PEM CA or self-signed server certificate to trust.
                  Required with -tls.
  -key file       Server PEM private-key file. Required with -tls.
  -c              Compress transferred data before encrypting/TLS transport.
                  Must be enabled on both client and server.

TLS certificates:
  The client verifies both the certificate chain and the hostname/IP supplied
  in host:port. The certificate must contain a matching Subject Alternative
  Name (SAN), such as DNS:example.com or IP:192.0.2.10.

Options:
  -p port         Listen or connect port when no port is provided in client mode
                  (default: 9999).
  -t seconds      I/O timeout in seconds; 0 disables the timeout (default: 0).
  -z              Check whether a TCP port is reachable; do not transfer data.
  -h              Show this help text.

Examples:
  # Custom encrypted transport with authenticated handshake.
  %s -l -k -a "a-long-random-secret"
  %s -a "a-long-random-secret" example.com:9999

  # Broadcast server-terminal input to several connected clients.
  %s -l -m

  # TLS using a self-signed certificate trusted by the client.
  %s -l -tls -cert cert.pem -key key.pem
  %s -tls -cert cert.pem localhost:9999

  # Receive one verified file, then exit.
  %s get -c received.iso

  # Send a file.
  %s send -c source.iso example.com:9999

`, os.Args[0], os.Args[0], os.Args[0], os.Args[0],
		os.Args[0], os.Args[0], os.Args[0], os.Args[0],
		os.Args[0], os.Args[0], os.Args[0])
}
