package helpers

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"io"
	"testing"
)

func TestWriteReadBytesWithLen(t *testing.T) {
	buf := &bytes.Buffer{}
	data := []byte("hello world")

	if err := WriteBytesWithLen(buf, data); err != nil {
		t.Fatalf("WriteBytesWithLen error: %v", err)
	}

	got, err := ReadBytesWithLen(buf)
	if err != nil {
		t.Fatalf("ReadBytesWithLen error: %v", err)
	}
	if !bytes.Equal(got, data) {
		t.Fatalf("mismatch: got %q want %q", got, data)
	}
}

func TestComputeAuth(t *testing.T) {
	psk := []byte("pre-shared-key")
	shared := []byte("shared-secret")

	got := ComputeAuth(psk, shared)

	m := hmac.New(sha256.New, psk)
	_, _ = io.WriteString(m, string(shared))
	want := m.Sum(nil)

	if !hmac.Equal(got, want) {
		t.Fatalf("ComputeAuth mismatch")
	}
}
