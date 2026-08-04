package connection

import (
	"bytes"
	"io"
	"net"
	"strings"
	"testing"
	"time"
)

func TestHandleConnReturnsWhenPeerCloses(t *testing.T) {
	serverConn, clientConn := net.Pipe()
	defer clientConn.Close()

	var output bytes.Buffer
	var diagnostics bytes.Buffer
	done := make(chan struct{})

	go func() {
		HandleConn(serverConn, &output, &diagnostics, 0)
		close(done)
	}()

	const message = "hello from client\n"
	if _, err := io.WriteString(clientConn, message); err != nil {
		t.Fatalf("client write error = %v", err)
	}

	_ = clientConn.Close()

	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("HandleConn did not return after peer closed")
	}

	if got := output.String(); got != message {
		t.Fatalf("server output = %q, want %q", got, message)
	}

	if !strings.Contains(diagnostics.String(), "connection closed") {
		t.Fatalf("diagnostics = %q, want connection close message", diagnostics.String())
	}
}
