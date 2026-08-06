package client

import (
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"time"

	"github.com/jnsoft/xfer/src/internal/connection"
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

	conn, err := net.Dial("tcp", config.Target)
	if err != nil {
		return fmt.Errorf("connect error: %w", err)
	}
	defer conn.Close()

	if err := connection.ReadAdmission(conn); err != nil {
		if errors.Is(err, connection.ErrServerBusy) {
			return fmt.Errorf("connect error: server is busy or full")
		} else {
			return fmt.Errorf("connect error: %w", err)
		}
	}

	var useConn net.Conn = conn
	if config.UseTLS {
		tlsConfig := config.TLSConfig
		if tlsConfig == nil {
			return errors.New("TLS configuration is required")
		}

		tlsConn := tls.Client(conn, tlsConfig)
		if err := tlsConn.Handshake(); err != nil {
			return fmt.Errorf("TLS handshake: %w", err)
		}
		useConn = tlsConn
		defer tlsConn.Close()
	} else if config.Secure {
		secureConn, err := connection.WrapWithAE(conn, false, config.Secret)
		if err != nil {
			return fmt.Errorf("handshake error: %w", err)
		}
		useConn = secureConn
		defer secureConn.Close()
	}

	if err := connection.NegotiateCompression(useConn, false, config.Compress); err != nil {
		return fmt.Errorf("compression setup error: %w", err)
	}

	if config.Compress {
		useConn = connection.WrapWithCompression(useConn)
	}

	connection.ApplyTimeout(useConn, config.Timeout)

	var wg sync.WaitGroup
	wg.Add(2)

	// stdin -> conn
	go func() {
		defer wg.Done()

		if _, err := io.Copy(useConn, config.Input); err != nil && !errors.Is(err, net.ErrClosed) {
			fmt.Fprintf(config.ErrorOutput, "send error: %v\n", err)
			_ = useConn.Close()
			return
		}

		// A normal stdin EOF only closes this direction; replies can still arrive.
		if cw, ok := useConn.(interface{ CloseWrite() error }); ok {
			_ = cw.CloseWrite()
		}
	}()

	// conn -> stdout
	go func() {
		defer wg.Done()

		copyServerOutput(config.Output, useConn, config.ErrorOutput)
	}()

	wg.Wait()
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
