package connection

import (
	"errors"
	"net"
	"testing"
)

func TestAdmissionAccepted(t *testing.T) {
	serverConn, clientConn := net.Pipe()
	defer serverConn.Close()
	defer clientConn.Close()

	serverErr := make(chan error, 1)
	go func() {
		serverErr <- SendAdmission(serverConn, true)
	}()

	if err := ReadAdmission(clientConn); err != nil {
		t.Fatalf("ReadAdmission() error = %v, want nil", err)
	}

	if err := <-serverErr; err != nil {
		t.Fatalf("SendAdmission() error = %v, want nil", err)
	}
}

func TestAdmissionBusy(t *testing.T) {
	serverConn, clientConn := net.Pipe()
	defer serverConn.Close()
	defer clientConn.Close()

	serverErr := make(chan error, 1)
	go func() {
		serverErr <- SendAdmission(serverConn, false)
	}()

	err := ReadAdmission(clientConn)
	if !errors.Is(err, ErrServerBusy) {
		t.Fatalf("ReadAdmission() error = %v, want ErrServerBusy", err)
	}

	if err := <-serverErr; err != nil {
		t.Fatalf("SendAdmission() error = %v, want nil", err)
	}
}

func TestAdmissionRejectsUnexpectedResponse(t *testing.T) {
	serverConn, clientConn := net.Pipe()
	defer serverConn.Close()
	defer clientConn.Close()

	serverErr := make(chan error, 1)
	go func() {
		_, err := serverConn.Write([]byte("XFER/1 UNKNOWN\n"))
		serverErr <- err
	}()

	err := ReadAdmission(clientConn)
	if err == nil {
		t.Fatal("ReadAdmission() error = nil, want invalid response error")
	}
	if errors.Is(err, ErrServerBusy) {
		t.Fatalf("ReadAdmission() error = %v, must not be ErrServerBusy", err)
	}

	if err := <-serverErr; err != nil {
		t.Fatalf("server write error = %v", err)
	}
}
