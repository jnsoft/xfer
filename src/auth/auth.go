package auth

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"io"

	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/hkdf"
)

// ComputeAuth derives a per-session MAC key using HKDF and computes an HMAC-SHA256
// over a transcript: context label + localPub + peerPub + shared.
//
// authKey: low-entropy pre-shared secret (may be zero-length).
// shared: ECDH shared secret (high entropy).
// localPub, peerPub: the public key bytes for transcript binding.
//
// Returns the MAC bytes or an error.
func ComputeAuth(authKey, shared, localPub, peerPub []byte) ([]byte, error) {
	// ensure a canonical ordering of the public keys so both peers derive the same transcript
	a := localPub
	b := peerPub
	if bytes.Compare(a, b) > 0 {
		a, b = b, a
	}
	// Derive a per-session salt from the high-entropy ECDH shared secret and the public keys.
	// This makes the Argon2 salt unique per-session without requiring extra round-trips.
	saltSeed := make([]byte, 0, len(shared)+len(a)+len(b))
	saltSeed = append(saltSeed, shared...)
	saltSeed = append(saltSeed, a...)
	saltSeed = append(saltSeed, b...)
	salt := sha256.Sum256(saltSeed)

	// Stretch the low-entropy authKey with Argon2id using the per-session salt.
	// Tune time/memory/threads as appropriate for your deployment.
	stretched := argon2.IDKey(authKey, salt[:], 3, 64*1024, 2, 32)

	// Use HKDF with the high-entropy shared secret as IKM and the stretched password as salt.
	macKey, err := GetHkdfKey(shared, stretched, []byte("xfer-v1 auth"), 32)
	if err != nil {
		// zero stretched before returning
		for i := range stretched {
			stretched[i] = 0
		}
		return nil, err
	}

	// compute HMAC over the transcript
	mac := hmac.New(sha256.New, macKey)
	mac.Write([]byte("xfer-v1 handshake"))
	mac.Write(a)
	mac.Write(b)
	mac.Write(shared)
	out := mac.Sum(nil)

	// zero sensitive buffers
	for i := range macKey {
		macKey[i] = 0
	}
	for i := range stretched {
		stretched[i] = 0
	}
	for i := range saltSeed {
		saltSeed[i] = 0
	}

	return out, nil
}

func GetHkdfKey(secret, salt, info []byte, keyLen int) ([]byte, error) {
	hk := hkdf.New(sha256.New, secret, salt, info)
	key := make([]byte, keyLen)
	if _, err := io.ReadFull(hk, key); err != nil {
		return nil, err
	}
	return key, nil
}


