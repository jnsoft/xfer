package server

import "testing"

func TestClientGateSingleClient(t *testing.T) {
	gate := NewClientGate(false)

	if !gate.TryAcquire() {
		t.Fatal("first client was rejected")
	}
	if gate.TryAcquire() {
		t.Fatal("second client was accepted")
	}

	gate.Release()

	if !gate.TryAcquire() {
		t.Fatal("client was rejected after the first client disconnected")
	}
}

func TestClientGateMultipleClients(t *testing.T) {
	gate := NewClientGate(true)

	if !gate.TryAcquire() {
		t.Fatal("first client was rejected")
	}
	if !gate.TryAcquire() {
		t.Fatal("second client was rejected")
	}
}
