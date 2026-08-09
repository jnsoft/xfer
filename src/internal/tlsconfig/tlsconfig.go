package tlsconfig

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"os"
)

func LoadClientTLSConfig(certFile, target string) (*tls.Config, error) {
	if certFile == "" {
		return nil, errors.New("-cert is required when using -tls")
	}

	certificatePEM, err := os.ReadFile(certFile)
	if err != nil {
		return nil, fmt.Errorf("read TLS certificate: %w", err)
	}

	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(certificatePEM) {
		return nil, errors.New("parse TLS certificate: no certificates found")
	}

	host, _, err := net.SplitHostPort(target)
	if err != nil {
		return nil, fmt.Errorf("invalid server address %q: %w", target, err)
	}

	return &tls.Config{
		MinVersion: tls.VersionTLS13,
		ServerName: host,
		RootCAs:    roots,
	}, nil
}

func LoadServerTLSConfig(certFile, keyFile string) (*tls.Config, error) {
	if certFile == "" || keyFile == "" {
		return nil, errors.New("-cert and -key are required when using -tls")
	}

	certificate, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return nil, fmt.Errorf("load TLS certificate and key: %w", err)
	}

	return &tls.Config{
		Certificates: []tls.Certificate{certificate},
		MinVersion:   tls.VersionTLS13,
	}, nil
}
