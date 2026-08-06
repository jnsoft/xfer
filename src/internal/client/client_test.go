package client

import (
	"bytes"
	"errors"
	"io"
	"net"
	"testing"
	"time"

	"github.com/jnsoft/xfer/src/internal/connection"
)

type errorReader struct {
	err error
}

func (r errorReader) Read([]byte) (int, error) {
	return 0, r.err
}

type blockingReader struct {
	release chan struct{}
}

func (r blockingReader) Read([]byte) (int, error) {
	<-r.release
	return 0, io.EOF
}

func TestCopyServerOutput(t *testing.T) {
	tests := []struct {
		name       string
		input      io.Reader
		wantOutput string
		wantStatus string
	}{
		{
			name:       "clean close",
			input:      bytes.NewBufferString("reply\n"),
			wantOutput: "reply\n",
			wantStatus: "server closed connection\n",
		},
		{
			name:       "truncated compressed stream",
			input:      errorReader{err: io.ErrUnexpectedEOF},
			wantStatus: "server closed connection unexpectedly\n",
		},
		{
			name:       "closed connection",
			input:      errorReader{err: net.ErrClosed},
			wantStatus: "server closed connection\n",
		},
		{
			name:       "other read error",
			input:      errorReader{err: errors.New("read failed")},
			wantStatus: "receive error: read failed\n",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var output bytes.Buffer
			var diagnostics bytes.Buffer

			copyServerOutput(&output, test.input, &diagnostics)

			if got := output.String(); got != test.wantOutput {
				t.Fatalf("output = %q, want %q", got, test.wantOutput)
			}
			if got := diagnostics.String(); got != test.wantStatus {
				t.Fatalf("diagnostics = %q, want %q", got, test.wantStatus)
			}
		})
	}
}

func TestRunClientRequiresStreams(t *testing.T) {
	tests := []struct {
		name   string
		config Config
		want   string
	}{
		{"missing input", Config{}, "client input is required"},
		{
			"missing output",
			Config{Input: bytes.NewReader(nil)},
			"client output is required",
		},
		{
			"missing error output",
			Config{
				Input:  bytes.NewReader(nil),
				Output: io.Discard,
			},
			"client error output is required",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			err := RunClient(test.config)
			if err == nil || err.Error() != test.want {
				t.Fatalf("RunClient() error = %v, want %q", err, test.want)
			}
		})
	}
}

func TestRunClientReturnsWhenServerCloses(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("net.Listen() error = %v", err)
	}
	defer listener.Close()

	serverDone := make(chan struct{})
	go func() {
		defer close(serverDone)

		conn, err := listener.Accept()
		if err != nil {
			return
		}
		defer conn.Close()

		_ = connection.SendAdmission(conn, true)
		_, _ = connection.NegotiateCapabilities(conn, true, false)
	}()

	input := blockingReader{release: make(chan struct{})}
	var output bytes.Buffer
	var diagnostics bytes.Buffer
	done := make(chan error, 1)

	go func() {
		done <- RunClient(Config{
			Target:      listener.Addr().String(),
			Secure:      false,
			Input:       input,
			Output:      &output,
			ErrorOutput: &diagnostics,
		})
	}()

	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("RunClient() error = %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("RunClient did not return after the server closed")
	}

	close(input.release)
	<-serverDone

	if got := diagnostics.String(); got != "server closed connection\n" {
		t.Fatalf("diagnostics = %q, want server closed message", got)
	}
}
