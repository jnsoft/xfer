package connection

import (
	"bytes"
	"errors"
	"io"
	"net"
	"strings"
	"testing"
	"time"
)

type negotiationResult struct {
	err error
}

func TestCompressedConnRoundTrip(t *testing.T) {
	serverRaw, clientRaw := net.Pipe()
	defer serverRaw.Close()
	defer clientRaw.Close()

	serverRaw.SetDeadline(time.Now().Add(time.Second))
	clientRaw.SetDeadline(time.Now().Add(time.Second))

	server := WrapWithCompression(serverRaw)
	client := WrapWithCompression(clientRaw)

	clientMessage := []byte(strings.Repeat("client data ", 4096))
	serverMessage := []byte(strings.Repeat("server data ", 4096))

	errs := make(chan error, 4)

	go func() {
		_, err := client.Write(clientMessage)
		errs <- err
	}()
	go func() {
		got := make([]byte, len(clientMessage))
		_, err := io.ReadFull(server, got)
		if err == nil && !bytes.Equal(got, clientMessage) {
			err = errors.New("server received different data")
		}
		errs <- err
	}()
	go func() {
		_, err := server.Write(serverMessage)
		errs <- err
	}()
	go func() {
		got := make([]byte, len(serverMessage))
		_, err := io.ReadFull(client, got)
		if err == nil && !bytes.Equal(got, serverMessage) {
			err = errors.New("client received different data")
		}
		errs <- err
	}()

	for range 4 {
		if err := <-errs; err != nil {
			t.Fatal(err)
		}
	}
}

func TestCompressedConnCloseWriteFinalizesStream(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("net.Listen() error = %v", err)
	}
	defer listener.Close()

	message := []byte(strings.Repeat("finalized compressed data ", 1024))
	result := make(chan struct {
		data []byte
		err  error
	}, 1)

	go func() {
		rawConn, err := listener.Accept()
		if err != nil {
			result <- struct {
				data []byte
				err  error
			}{err: err}
			return
		}
		defer rawConn.Close()

		if err := rawConn.SetDeadline(time.Now().Add(time.Second)); err != nil {
			result <- struct {
				data []byte
				err  error
			}{err: err}
			return
		}

		data, err := io.ReadAll(WrapWithCompression(rawConn))
		result <- struct {
			data []byte
			err  error
		}{data: data, err: err}
	}()

	rawConn, err := net.Dial("tcp", listener.Addr().String())
	if err != nil {
		t.Fatalf("net.Dial() error = %v", err)
	}
	defer rawConn.Close()

	if err := rawConn.SetDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatalf("SetDeadline() error = %v", err)
	}

	client := WrapWithCompression(rawConn)
	if _, err := client.Write(message); err != nil {
		t.Fatalf("Write() error = %v", err)
	}
	if err := client.CloseWrite(); err != nil {
		t.Fatalf("CloseWrite() error = %v", err)
	}

	got := <-result
	if got.err != nil {
		t.Fatalf("server read error = %v", got.err)
	}
	if !bytes.Equal(got.data, message) {
		t.Fatalf("server received %d bytes, want %d", len(got.data), len(message))
	}
}

func TestNegotiateCompression(t *testing.T) {
	tests := []struct {
		name          string
		serverEnabled bool
		clientEnabled bool
		wantErr       bool
	}{
		{"both disabled", false, false, false},
		{"both enabled", true, true, false},
		{"server only", true, false, true},
		{"client only", false, true, true},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			server, client := net.Pipe()
			defer server.Close()
			defer client.Close()

			results := make(chan negotiationResult, 2)

			go func() {
				results <- negotiationResult{
					err: NegotiateCompression(server, true, test.serverEnabled),
				}
			}()
			go func() {
				results <- negotiationResult{
					err: NegotiateCompression(client, false, test.clientEnabled),
				}
			}()

			for range 2 {
				err := (<-results).err
				if test.wantErr {
					if !errors.Is(err, ErrCompressionMismatch) {
						t.Fatalf("NegotiateCompression() error = %v, want ErrCompressionMismatch", err)
					}
					continue
				}
				if err != nil {
					t.Fatalf("NegotiateCompression() error = %v, want nil", err)
				}
			}
		})
	}
}
