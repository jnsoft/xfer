package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"time"

	"github.com/jnsoft/xfer/src/internal/client"
	"github.com/jnsoft/xfer/src/internal/server"
)

const (
	maxClients     = 1024
	defaultAddress = "127.0.0.1" // if no host:port provided, use localhost:port
)

type Options struct {
	Listen   bool
	Keep     bool
	Multi    bool
	Port     int
	Timeout  time.Duration
	Secure   bool
	Auth     string
	TLS      bool
	CertFile string
	KeyFile  string
	Compress bool
	ZeroIO   bool
	Help     bool
}

func parseOptions(args []string) (Options, []string, error) {
	options := Options{
		Port:   9999,
		Secure: true,
	}

	flags := flag.NewFlagSet("xfer", flag.ContinueOnError)
	flags.SetOutput(io.Discard)

	flags.BoolVar(&options.Listen, "l", false, "listen mode")
	flags.BoolVar(&options.Keep, "k", false, "keep listening")
	flags.BoolVar(&options.Multi, "m", false, "allow simultaneous clients")
	flags.IntVar(&options.Port, "p", 9999, "port")
	flags.DurationVar(&options.Timeout, "t", 0, "I/O timeout")
	flags.BoolVar(&options.Secure, "s", true, "use secure AES-256-GCM + ECDH transport")
	flags.StringVar(&options.Auth, "a", "", "pre-shared authentication key (mitm protection)")
	flags.BoolVar(&options.TLS, "tls", false, "use TLS 1.3")
	flags.StringVar(&options.CertFile, "cert", "", "TLS certificate")
	flags.StringVar(&options.KeyFile, "key", "", "TLS private key")
	flags.BoolVar(&options.Compress, "c", false, "compress data")
	flags.BoolVar(&options.ZeroIO, "z", false, "check TCP reachability")
	flags.BoolVar(&options.Help, "h", false, "show help")

	if err := flags.Parse(args); err != nil {
		return Options{}, nil, err
	}
	if options.Port < 1 || options.Port > 65535 {
		return Options{}, nil, fmt.Errorf("invalid port %d", options.Port)
	}

	if options.Timeout < 0 {
		return Options{}, nil, fmt.Errorf("invalid timeout %v", options.Timeout)
	}

	return options, flags.Args(), nil
}

// target returns explicit host:port
func (options Options) target(arguments []string) (string, error) {
	switch len(arguments) {
	case 0:
		return net.JoinHostPort(defaultAddress, fmt.Sprint(options.Port)), nil
	case 1:
		return arguments[0], nil
	default:
		return "", errors.New("expected at most one host:port")
	}
}

func (options Options) clientConfig(target string) client.Config {
	return client.Config{
		Target:   target,
		Timeout:  options.Timeout,
		Secure:   options.Secure,
		UseTLS:   options.TLS,
		Compress: options.Compress,
		Secret:   options.Auth,
	}
}

func (options Options) serverConfig() server.Config {
	return server.Config{
		Addr:          fmt.Sprintf(":%d", options.Port),
		KeepListening: options.Keep,
		AllowMultiple: options.Multi,
		MaxClients:    maxClients,
		Timeout:       options.Timeout,
		Secure:        options.Secure,
		UseTLS:        options.TLS,
		Compress:      options.Compress,
		Secret:        options.Auth,
	}
}
