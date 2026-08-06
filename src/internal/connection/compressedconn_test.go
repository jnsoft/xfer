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

type capabilityResult struct {
	compress bool
	err      error
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

func TestNegotiateCapabilities(t *testing.T) {
	tests := []struct {
		name          string
		serverEnabled bool
		clientEnabled bool
		wantCompress  bool
		wantErr       error
	}{
		{"both disabled", false, false, false, nil},
		{"both enabled", true, true, true, nil},
		{"server only", true, false, false, ErrCompressionMismatch},
		{"client only", false, true, false, ErrCompressionMismatch},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			server, client := net.Pipe()
			defer server.Close()
			defer client.Close()

			results := make(chan capabilityResult, 2)

			go func() {
				compress, err := NegotiateCapabilities(server, true, test.serverEnabled)
				results <- capabilityResult{compress: compress, err: err}
			}()

			go func() {
				compress, err := NegotiateCapabilities(client, false, test.clientEnabled)
				results <- capabilityResult{compress: compress, err: err}
			}()

			for range 2 {
				result := <-results

				if test.wantErr != nil {
					if !errors.Is(result.err, test.wantErr) {
						t.Fatalf("NegotiateCapabilities() error = %v, want %v", result.err, test.wantErr)
					}
					continue
				}

				if result.err != nil {
					t.Fatalf("NegotiateCapabilities() error = %v, want nil", result.err)
				}
				if result.compress != test.wantCompress {
					t.Fatalf("compression = %t, want %t", result.compress, test.wantCompress)
				}
			}
		})
	}
}

func TestNegotiateCapabilitiesRejectsInvalidMagic(t *testing.T) {
	server, client := net.Pipe()
	defer server.Close()
	defer client.Close()

	go func() {
		_, _ = readHello(server)

		var invalidHello [helloSize]byte
		copy(invalidHello[:4], "NOPE")
		invalidHello[4] = helloVersion
		_, _ = server.Write(invalidHello[:])
	}()

	_, err := NegotiateCapabilities(client, false, false)
	if err == nil {
		t.Fatal("NegotiateCapabilities() error = nil, want invalid protocol hello")
	}
	if !strings.Contains(err.Error(), "invalid protocol hello") {
		t.Fatalf("NegotiateCapabilities() error = %v, want invalid protocol hello", err)
	}
}

func TestNegotiateCapabilitiesRejectsUnsupportedVersion(t *testing.T) {
	server, client := net.Pipe()
	defer server.Close()
	defer client.Close()

	go func() {
		_, _ = readHello(server)

		var unsupportedHello [helloSize]byte
		copy(unsupportedHello[:4], "XFR2")
		unsupportedHello[4] = helloVersion + 1
		_, _ = server.Write(unsupportedHello[:])
	}()

	_, err := NegotiateCapabilities(client, false, false)
	if !errors.Is(err, ErrProtocolVersion) {
		t.Fatalf("NegotiateCapabilities() error = %v, want ErrProtocolVersion", err)
	}
}
