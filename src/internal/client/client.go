package client

import (
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"time"

	"github.com/jnsoft/xfer/src/internal/connection"
	"github.com/jnsoft/xfer/src/internal/filetransfer"
)

type Config struct {
	Target      string
	Timeout     time.Duration
	Secure      bool
	UseTLS      bool
	Compress    bool
	Secret      string
	TLSConfig   *tls.Config
	Input       io.Reader
	Output      io.Writer
	ErrorOutput io.Writer
}

type FileConfig struct {
	Connection Config
	SourcePath string
}

func RunClient(config Config) error {
	if config.Input == nil {
		return errors.New("client input is required")
	}
	if config.Output == nil {
		return errors.New("client output is required")
	}
	if config.ErrorOutput == nil {
		return errors.New("client error output is required")
	}

	useConn, err := Connect(config)
	if err != nil {
		return err
	}
	defer useConn.Close()

	receivedDone := make(chan struct{})

	// input -> server
	go func() {
		if _, err := io.Copy(useConn, config.Input); err != nil &&
			!errors.Is(err, net.ErrClosed) {
			fmt.Fprintf(config.ErrorOutput, "send error: %v\n", err)
			_ = useConn.Close()
			return
		}

		if closeWriter, ok := useConn.(interface{ CloseWrite() error }); ok {
			_ = closeWriter.CloseWrite()
		}
	}()

	// server -> output
	go func() {
		defer close(receivedDone)

		copyServerOutput(config.Output, useConn, config.ErrorOutput)
		_ = useConn.Close()
	}()

	<-receivedDone
	return nil
}

func CheckPort(target string, timeout time.Duration) error {
	conn, err := net.DialTimeout("tcp", target, timeout)
	if err != nil {
		return err
	}
	return conn.Close()
}

func copyServerOutput(output io.Writer, input io.Reader, diagnostics io.Writer) {
	if _, err := io.Copy(output, input); err != nil {
		switch {
		case errors.Is(err, net.ErrClosed):
			fmt.Fprintln(diagnostics, "server closed connection")
		case errors.Is(err, io.ErrUnexpectedEOF):
			fmt.Fprintln(diagnostics, "server closed connection unexpectedly")
		default:
			fmt.Fprintf(diagnostics, "receive error: %v\n", err)
		}
		return
	}

	fmt.Fprintln(diagnostics, "server closed connection")
}

func Connect(config Config) (net.Conn, error) {
	conn, err := net.Dial("tcp", config.Target)
	if err != nil {
		return nil, fmt.Errorf("connect error: %w", err)
	}

	closeOnError := true
	defer func() {
		if closeOnError {
			_ = conn.Close()
		}
	}()

	if err := connection.ReadAdmission(conn); err != nil {
		if errors.Is(err, connection.ErrServerBusy) {
			return nil, errors.New("connect error: server is busy or full")
		}
		return nil, fmt.Errorf("connect error: %w", err)
	}

	var useConn net.Conn = conn
	if config.UseTLS {
		if config.TLSConfig == nil {
			return nil, errors.New("TLS configuration is required")
		}

		tlsConn := tls.Client(conn, config.TLSConfig)
		if err := tlsConn.Handshake(); err != nil {
			return nil, fmt.Errorf("TLS handshake: %w", err)
		}
		useConn = tlsConn
	} else if config.Secure {
		secureConn, err := connection.WrapWithAE(conn, false, config.Secret)
		if err != nil {
			return nil, fmt.Errorf("handshake error: %w", err)
		}
		useConn = secureConn
	}

	compress, err := connection.NegotiateCapabilities(useConn, false, config.Compress)
	if err != nil {
		return nil, fmt.Errorf("protocol negotiation: %w", err)
	}
	if compress {
		useConn = connection.WrapWithCompression(useConn)
	}

	connection.ApplyTimeout(useConn, config.Timeout)
	closeOnError = false
	return useConn, nil
}

func SendFile(config FileConfig) error {
	conn, err := Connect(config.Connection)
	if err != nil {
		return err
	}
	defer conn.Close()
	return filetransfer.Send(conn, config.SourcePath)
}
