package auth

import (
	"crypto/hmac"
	"testing"
)

func TestComputeAuth(t *testing.T) {
	psk := []byte("pre-shared-key")
	shared := []byte("shared-secret")
	localPub := []byte("local-pub")
	peerPub := []byte("peer-pub")

	got1, err := ComputeAuth(psk, shared, localPub, peerPub)
	if err != nil {
		t.Fatalf("ComputeAuth error: %v", err)
	}
	got2, err := ComputeAuth(psk, shared, peerPub, localPub)
	if err != nil {
		t.Fatalf("ComputeAuth error: %v", err)
	}

	if !hmac.Equal(got1, got2) {
		t.Fatalf("ComputeAuth not deterministic: got1 != got2")
	}
	if len(got1) != 32 {
		t.Fatalf("ComputeAuth output length = %d, want 32", len(got1))
	}

	got3, _ := ComputeAuth([]byte("other-psk"), shared, localPub, peerPub)
	if hmac.Equal(got1, got3) {
		t.Fatalf("ComputeAuth should differ when PSK changes")
	}
}
