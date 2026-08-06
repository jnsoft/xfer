package server

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jnsoft/xfer/src/internal/connection"
)

type lockedBuffer struct {
	mu     sync.Mutex
	buffer bytes.Buffer
}

func (b *lockedBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()

	return b.buffer.Write(p)
}

func (b *lockedBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()

	return b.buffer.String()
}

func startTestServer(t *testing.T, config Config) (net.Listener, <-chan error, *lockedBuffer) {
	t.Helper()

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("net.Listen() error = %v", err)
	}

	if config.Input == nil {
		config.Input = strings.NewReader("")
	}
	if config.Output == nil {
		config.Output = io.Discard
	}

	var diagnostics lockedBuffer
	config.ErrorOutput = &diagnostics

	done := make(chan error, 1)
	go func() {
		done <- Serve(context.Background(), listener, config)
	}()

	return listener, done, &diagnostics
}

func stopTestServer(t *testing.T, listener net.Listener, done <-chan error) {
	t.Helper()

	if err := listener.Close(); err != nil {
		t.Fatalf("listener.Close() error = %v", err)
	}

	select {
	case err := <-done:
		if err != nil && !errors.Is(err, net.ErrClosed) {
			t.Fatalf("Serve() error = %v, want net.ErrClosed", err)
		}
	case <-time.After(time.Second):
		t.Fatal("Serve() did not return after listener.Close()")
	}
}

func connectAndReadAdmission(t *testing.T, address string) net.Conn {
	return connectAndReadAdmissionWithCompression(t, address, false)
}

func connectAndReadAdmissionWithCompression(t *testing.T, address string, compress bool) net.Conn {
	t.Helper()

	conn, err := net.Dial("tcp", address)
	if err != nil {
		t.Fatalf("net.Dial() error = %v", err)
	}

	if err := connection.ReadAdmission(conn); err != nil {
		_ = conn.Close()
		t.Fatalf("ReadAdmission() error = %v, want nil", err)
	}

	if err := connection.NegotiateCompression(conn, false, compress); err != nil {
		_ = conn.Close()
		t.Fatalf("NegotiateCompression() error = %v", err)
	}

	return conn
}

func readLine(t *testing.T, conn net.Conn) string {
	t.Helper()

	if err := conn.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatalf("SetReadDeadline() error = %v", err)
	}
	defer conn.SetReadDeadline(time.Time{})

	line, err := bufio.NewReader(conn).ReadString('\n')
	if err != nil {
		t.Fatalf("ReadString() error = %v", err)
	}

	return line
}

func TestServeRejectsSecondSingleClientAndAcceptsReconnect(t *testing.T) {
	listener, done, diagnostics := startTestServer(t, Config{
		KeepListening: true,
		Secure:        false,
	})
	defer stopTestServer(t, listener, done)

	firstClient := connectAndReadAdmission(t, listener.Addr().String())

	secondClient, err := net.Dial("tcp", listener.Addr().String())
	if err != nil {
		t.Fatalf("second net.Dial() error = %v", err)
	}

	err = connection.ReadAdmission(secondClient)
	_ = secondClient.Close()
	if !errors.Is(err, connection.ErrServerBusy) {
		t.Fatalf("second ReadAdmission() error = %v, want ErrServerBusy", err)
	}

	_ = firstClient.Close()

	deadline := time.Now().Add(time.Second)
	for {
		thirdClient, err := net.Dial("tcp", listener.Addr().String())
		if err != nil {
			t.Fatalf("third net.Dial() error = %v", err)
		}

		admissionErr := connection.ReadAdmission(thirdClient)
		if admissionErr == nil {
			_ = thirdClient.Close()
			break
		}

		_ = thirdClient.Close()

		if !errors.Is(admissionErr, connection.ErrServerBusy) {
			t.Fatalf("third ReadAdmission() error = %v, want nil or ErrServerBusy", admissionErr)
		}
		if time.Now().After(deadline) {
			t.Fatal("server did not accept a replacement client after first client closed")
		}

		time.Sleep(10 * time.Millisecond)
	}

	gotDiagnostics := diagnostics.String()
	if !strings.Contains(gotDiagnostics, "connection rejected from") {
		t.Fatalf("diagnostics = %q, want rejected connection message", gotDiagnostics)
	}
}

func TestServeAllowsMultipleClients(t *testing.T) {
	listener, done, _ := startTestServer(t, Config{
		AllowMultiple: true,
		Secure:        false,
	})
	defer stopTestServer(t, listener, done)

	firstClient := connectAndReadAdmission(t, listener.Addr().String())
	defer firstClient.Close()

	secondClient := connectAndReadAdmission(t, listener.Addr().String())
	defer secondClient.Close()
}

func TestServeBroadcastsInputToAllClients(t *testing.T) {
	inputReader, inputWriter := io.Pipe()
	defer inputWriter.Close()

	listener, done, _ := startTestServer(t, Config{
		AllowMultiple: true,
		Secure:        false,
		Input:         inputReader,
	})
	defer stopTestServer(t, listener, done)

	firstClient := connectAndReadAdmission(t, listener.Addr().String())
	defer firstClient.Close()

	secondClient := connectAndReadAdmission(t, listener.Addr().String())
	defer secondClient.Close()

	if _, err := io.WriteString(inputWriter, "hello clients\n"); err != nil {
		t.Fatalf("input write error = %v", err)
	}

	if got := readLine(t, firstClient); got != "hello clients\n" {
		t.Fatalf("first client received %q, want %q", got, "hello clients\n")
	}

	if got := readLine(t, secondClient); got != "hello clients\n" {
		t.Fatalf("second client received %q, want %q", got, "hello clients\n")
	}
}

func TestServeForwardsClientOutput(t *testing.T) {
	var output lockedBuffer

	listener, done, _ := startTestServer(t, Config{
		KeepListening: true,
		Secure:        false,
		Output:        &output,
	})
	defer stopTestServer(t, listener, done)

	client := connectAndReadAdmission(t, listener.Addr().String())

	const message = "hello from client\n"
	if _, err := io.WriteString(client, message); err != nil {
		t.Fatalf("client write error = %v", err)
	}
	_ = client.Close()

	deadline := time.Now().Add(time.Second)
	for !strings.Contains(output.String(), message) {
		if time.Now().After(deadline) {
			t.Fatalf("server output = %q, want %q", output.String(), message)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func TestServeReturnsWhenListenerCloses(t *testing.T) {
	listener, done, _ := startTestServer(t, Config{
		Secure: false,
	})

	stopTestServer(t, listener, done)
}

func TestServeRejectsClientsOverLimit(t *testing.T) {
	listener, done, _ := startTestServer(t, Config{
		AllowMultiple: true,
		MaxClients:    1,
		Secure:        false,
	})
	defer stopTestServer(t, listener, done)

	firstClient := connectAndReadAdmission(t, listener.Addr().String())
	defer firstClient.Close()

	secondClient, err := net.Dial("tcp", listener.Addr().String())
	if err != nil {
		t.Fatalf("second net.Dial() error = %v", err)
	}
	defer secondClient.Close()

	if err := connection.ReadAdmission(secondClient); !errors.Is(err, connection.ErrServerBusy) {
		t.Fatalf("second ReadAdmission() error = %v, want ErrServerBusy", err)
	}
}

func TestServeReleasesSlotAfterHandshakeTimeout(t *testing.T) {
	listener, done, _ := startTestServer(t, Config{
		AllowMultiple:    true,
		MaxClients:       1,
		Secure:           true,
		HandshakeTimeout: 20 * time.Millisecond,
	})
	defer stopTestServer(t, listener, done)

	stalledClient, err := net.Dial("tcp", listener.Addr().String())
	if err != nil {
		t.Fatalf("stalled net.Dial() error = %v", err)
	}
	defer stalledClient.Close()

	if err := connection.ReadAdmission(stalledClient); err != nil {
		t.Fatalf("stalled ReadAdmission() error = %v", err)
	}

	deadline := time.Now().Add(time.Second)
	for {
		nextClient, err := net.Dial("tcp", listener.Addr().String())
		if err != nil {
			t.Fatalf("next net.Dial() error = %v", err)
		}

		admissionErr := connection.ReadAdmission(nextClient)
		_ = nextClient.Close()

		if admissionErr == nil {
			break
		}

		if !errors.Is(admissionErr, connection.ErrServerBusy) {
			t.Fatalf("next ReadAdmission() error = %v, want nil or ErrServerBusy", admissionErr)
		}
		if time.Now().After(deadline) {
			t.Fatal("server did not release the slot after handshake timeout")
		}

		time.Sleep(10 * time.Millisecond)
	}
}

func TestServeFailsBeforeAcceptingWithInvalidTLSConfiguration(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("net.Listen() error = %v", err)
	}
	defer listener.Close()

	err = Serve(context.Background(), listener, Config{
		UseTLS:      true,
		Input:       strings.NewReader(""),
		Output:      io.Discard,
		ErrorOutput: io.Discard,
	})

	if err == nil {
		t.Fatal("Serve() error = nil, want TLS configuration error")
	}
	if !strings.Contains(err.Error(), "TLS configuration is required") {
		t.Fatalf("Serve() error = %v, want TLS configuration error", err)
	}
}

func TestServeForwardsCompressedClientOutput(t *testing.T) {
	var output lockedBuffer

	listener, done, _ := startTestServer(t, Config{
		KeepListening: true,
		Secure:        false,
		Compress:      true,
		Output:        &output,
	})
	defer stopTestServer(t, listener, done)

	rawClient := connectAndReadAdmissionWithCompression(t, listener.Addr().String(), true)
	defer rawClient.Close()

	client := connection.WrapWithCompression(rawClient)
	const message = "compressed client message\n"

	if _, err := io.WriteString(client, message); err != nil {
		t.Fatalf("client Write() error = %v", err)
	}
	if err := client.CloseWrite(); err != nil {
		t.Fatalf("client CloseWrite() error = %v", err)
	}

	deadline := time.Now().Add(time.Second)
	for !strings.Contains(output.String(), message) {
		if time.Now().After(deadline) {
			t.Fatalf("server output = %q, want %q", output.String(), message)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func TestServeBroadcastsCompressedInput(t *testing.T) {
	inputReader, inputWriter := io.Pipe()
	defer inputWriter.Close()

	listener, done, _ := startTestServer(t, Config{
		AllowMultiple: true,
		Secure:        false,
		Compress:      true,
		Input:         inputReader,
	})
	defer stopTestServer(t, listener, done)

	rawClient := connectAndReadAdmissionWithCompression(t, listener.Addr().String(), true)
	defer rawClient.Close()

	client := connection.WrapWithCompression(rawClient)
	defer client.Close()

	const message = "compressed server message\n"
	if _, err := io.WriteString(inputWriter, message); err != nil {
		t.Fatalf("input Write() error = %v", err)
	}

	if got := readLine(t, client); got != message {
		t.Fatalf("client received %q, want %q", got, message)
	}
}
