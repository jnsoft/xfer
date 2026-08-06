package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/jnsoft/xfer/src/internal/client"
	"github.com/jnsoft/xfer/src/internal/server"
	"github.com/jnsoft/xfer/src/internal/terminal"
	"golang.org/x/term"
)

const (
	maxClients     = 1024
	defaultAddress = "127.0.0.1" // if no host:port provided, use localhost:port
)

var (
	flagListen   = flag.Bool("l", false, "listen mode (server)")
	flagKeep     = flag.Bool("k", false, "keep listening after a connection closes (server)")
	flagMulti    = flag.Bool("m", false, "allow simultaneous clients; broadcast server input (server)")
	flagPort     = flag.Int("p", 9999, "port to listen on or connect to")
	flagTimeout  = flag.Int("t", 0, "I/O timeout seconds (0 = no timeout)")
	flagSecure   = flag.Bool("s", true, "use secure AES-256-GCM + ECDH transport")
	flagAuth     = flag.String("a", "", "optional pre-shared key to authenticate the handshake (mitm protection)")
	flagTLS      = flag.Bool("tls", false, "use TLS 1.3 transport")
	flagCert     = flag.String("cert", "", "TLS certificate file (required for TLS)")
	flagKey      = flag.String("key", "", "TLS private key file (server, required for TLS)")
	flagCompress = flag.Bool("c", false, "compress data before transport")
	flagZeroIO   = flag.Bool("z", false, "check whether a TCP port is reachable")
	flagHelp     = flag.Bool("h", false, "show help")
)

func main() {
	flag.Usage = usage
	flag.Parse()
	if *flagHelp {
		usage()
		return
	}

	target := ""
	if flag.NArg() > 0 {
		target = flag.Arg(0)
	} else {
		target = fmt.Sprintf("%s:%d", defaultAddress, *flagPort)
	}

	if *flagTLS && *flagCert == "" {
		fmt.Fprintln(os.Stderr, "Error: -cert is required when using -tls")
		os.Exit(2)
	}
	if *flagTLS && *flagListen && *flagKey == "" {
		fmt.Fprintln(os.Stderr, "Error: -key is required for server when using -tls")
		os.Exit(2)
	}

	var clientTLSConfig *tls.Config
	var serverTLSConfig *tls.Config

	if *flagTLS {
		if *flagListen {
			certificate, err := tls.LoadX509KeyPair(*flagCert, *flagKey)
			if err != nil {
				fmt.Fprintf(os.Stderr, "load TLS certificate and key: %v\n", err)
				os.Exit(2)
			}

			serverTLSConfig = &tls.Config{
				Certificates: []tls.Certificate{certificate},
				MinVersion:   tls.VersionTLS13,
			}
		} else {
			certificatePEM, err := os.ReadFile(*flagCert)
			if err != nil {
				fmt.Fprintf(os.Stderr, "read TLS certificate: %v\n", err)
				os.Exit(2)
			}

			roots := x509.NewCertPool()
			if !roots.AppendCertsFromPEM(certificatePEM) {
				fmt.Fprintln(os.Stderr, "parse TLS certificate: no certificates found")
				os.Exit(2)
			}

			host, _, err := net.SplitHostPort(target)
			if err != nil {
				fmt.Fprintf(os.Stderr, "invalid server address %q: %v\n", target, err)
				os.Exit(2)
			}

			clientTLSConfig = &tls.Config{
				MinVersion: tls.VersionTLS13,
				ServerName: host,
				RootCAs:    roots,
			}
		}
	}

	timeout := time.Duration(*flagTimeout) * time.Second

	// setup interrupt handling to close cleanly
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	if *flagListen {
		addr := fmt.Sprintf(":%d", *flagPort)

		serverOutput := io.Writer(os.Stdout)

		if term.IsTerminal(int(os.Stdout.Fd())) {
			serverOutput = terminal.NewWriter(os.Stdout)
		}
		err := server.Run(ctx, server.Config{
			Addr:          addr,
			KeepListening: *flagKeep,
			AllowMultiple: *flagMulti,
			MaxClients:    maxClients,
			Timeout:       timeout,
			Secure:        *flagSecure,
			UseTLS:        *flagTLS,
			Compress:      *flagCompress,
			Secret:        *flagAuth,
			TLSConfig:     serverTLSConfig,
			Input:         os.Stdin,
			Output:        serverOutput,
			ErrorOutput:   os.Stderr,
		})
		if err != nil {
			fmt.Fprintf(os.Stderr, "server error: %v\n", err)
			os.Exit(2)
		}
		return
	}

	if *flagZeroIO {
		timeout := 5 * time.Second
		if *flagTimeout > 0 {
			timeout = time.Duration(*flagTimeout) * time.Second
		}

		if err := client.CheckPort(target, timeout); err != nil {
			fmt.Fprintf(os.Stderr, "%s: connection failed: %v\n", target, err)
			os.Exit(1)
		}

		fmt.Fprintf(os.Stderr, "%s: connection succeeded\n", target)
		return
	}

	if err := client.RunClient(client.Config{
		Target:      target,
		Timeout:     timeout,
		Secure:      *flagSecure,
		UseTLS:      *flagTLS,
		Compress:    *flagCompress,
		Secret:      *flagAuth,
		TLSConfig:   clientTLSConfig,
		Input:       os.Stdin,
		Output:      os.Stdout,
		ErrorOutput: os.Stderr,
	}); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
}

func usage() {
	fmt.Fprintf(os.Stderr, `Usage:
  %s [options] [host:port]
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

`, os.Args[0], os.Args[0], os.Args[0], os.Args[0], os.Args[0], os.Args[0], os.Args[0])
}
