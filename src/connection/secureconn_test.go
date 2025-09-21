package connection

import (
	"io"
	"net"
	"runtime"
	"sync"
	"testing"
	"time"
)

type wrapResult struct {
	conn net.Conn
	err  error
	id   string
}

func runWrapAsync(c net.Conn, isServer bool, key string, id string, ch chan<- wrapResult) {
	_ = c.SetDeadline(time.Now().Add(1000 * time.Millisecond))
	// WrapWithAE returns *SecureConn which implements net.Conn
	sc, err := WrapWithAE(c, isServer, key)
	_ = c.SetDeadline(time.Time{})
	ch <- wrapResult{conn: sc, err: err, id: id}
}

func dumpStacks(t *testing.T) {
	buf := make([]byte, 1<<20)
	n := runtime.Stack(buf, true)
	t.Logf("=== goroutine stack dump ===\n%s", buf[:n])
}

func TestSecureConn_NoAuth_RoundTrip(t *testing.T) {
	go func() {
		<-time.After(2 * time.Second)
		dumpStacks(t)
	}()

	c1, c2 := net.Pipe()
	defer c1.Close()
	defer c2.Close()

	ch := make(chan wrapResult, 2)
	go runWrapAsync(c1, true, "", "server", ch)
	go runWrapAsync(c2, false, "", "client", ch)

	var serverRes, clientRes wrapResult
	timeout := time.After(2 * time.Second)
	for i := 0; i < 2; i++ {
		select {
		case r := <-ch:
			if r.id == "server" {
				serverRes = r
			} else {
				clientRes = r
			}
		case <-timeout:
			t.Fatal("handshake timed out")
		}
	}

	if serverRes.err != nil {
		t.Fatalf("server handshake error: %v", serverRes.err)
	}
	if clientRes.err != nil {
		t.Fatalf("client handshake error: %v", clientRes.err)
	}

	// client -> server
	msg1 := []byte("hello from client")
	n, err := clientRes.conn.Write(msg1)
	if err != nil {
		t.Fatalf("client write error: %v", err)
	}
	if n != len(msg1) {
		t.Fatalf("client wrote %d bytes, want %d", n, len(msg1))
	}

	buf := make([]byte, len(msg1))
	if _, err := io.ReadFull(serverRes.conn, buf); err != nil {
		t.Fatalf("server read error: %v", err)
	}
	if string(buf) != string(msg1) {
		t.Fatalf("server got %q want %q", buf, msg1)
	}

	// server -> client
	msg2 := []byte("reply from server")
	if _, err := serverRes.conn.Write(msg2); err != nil {
		t.Fatalf("server write error: %v", err)
	}
	buf2 := make([]byte, len(msg2))
	if _, err := io.ReadFull(clientRes.conn, buf2); err != nil {
		t.Fatalf("client read error: %v", err)
	}
	if string(buf2) != string(msg2) {
		t.Fatalf("client got %q want %q", buf2, msg2)
	}

	_ = serverRes.conn.Close()
	_ = clientRes.conn.Close()
}

func TestSecureConn_WithAuth_MatchingKey(t *testing.T) {
	c1, c2 := net.Pipe()
	defer c1.Close()
	defer c2.Close()

	const psk = "my-secret-key"
	ch := make(chan wrapResult, 2)
	go runWrapAsync(c1, true, psk, "server", ch)
	go runWrapAsync(c2, false, psk, "client", ch)

	var serverRes, clientRes wrapResult
	timeout := time.After(2 * time.Second)
	for i := 0; i < 2; i++ {
		select {
		case r := <-ch:
			if r.id == "server" {
				serverRes = r
			} else {
				clientRes = r
			}
		case <-timeout:
			t.Fatal("handshake timed out")
		}
	}

	if serverRes.err != nil || clientRes.err != nil {
		t.Fatalf("handshake failed: serverErr=%v clientErr=%v", serverRes.err, clientRes.err)
	}

	// basic roundtrip
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		msg := []byte("ping")
		if _, err := clientRes.conn.Write(msg); err != nil {
			t.Errorf("client write: %v", err)
		}
	}()
	go func() {
		defer wg.Done()
		buf := make([]byte, 4)
		if _, err := io.ReadFull(serverRes.conn, buf); err != nil {
			t.Errorf("server read: %v", err)
		}
	}()
	wg.Wait()

	_ = serverRes.conn.Close()
	_ = clientRes.conn.Close()
}

func TestSecureConn_WithAuth_MismatchedKeyFails(t *testing.T) {
	c1, c2 := net.Pipe()
	defer c1.Close()
	defer c2.Close()

	ch := make(chan wrapResult, 2)
	go runWrapAsync(c1, true, "server-key", "server", ch)
	go runWrapAsync(c2, false, "client-key", "client", ch)

	var serverRes, clientRes wrapResult
	timeout := time.After(2 * time.Second)
	for i := 0; i < 2; i++ {
		select {
		case r := <-ch:
			if r.id == "server" {
				serverRes = r
			} else {
				clientRes = r
			}
		case <-timeout:
			t.Fatal("handshake timed out")
		}
	}

	// At least one side should have returned an error due to auth mismatch.
	if serverRes.err == nil && clientRes.err == nil {
		t.Fatalf("expected authentication failure but both handshakes succeeded")
	}

	// close any successful wrapped connections
	/*
		if serverRes.conn != nil {
			_ = serverRes.conn.Close()
		}
		if clientRes.conn != nil {
			_ = clientRes.conn.Close()
		} */
}
