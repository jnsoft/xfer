package helpers

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

func ComputeAuth_old(authKey, shared []byte) []byte {
	salt := sha256.Sum256(shared)
	// Argon2id parameters — tune based on your environment. Current values are reasonable for servers:
	//   time = 3 iterations, memory = 64 MB, threads = 2, keyLen = 32 bytes
	// If you need faster or lower-memory operation (e.g. constrained devices), reduce memory/time.
	derived := argon2.IDKey(authKey, salt[:], 3, 64*1024, 2, 32)
	mac := hmac.New(sha256.New, derived)
	mac.Write([]byte("xfer-v1 handshake"))
	mac.Write(shared)
	return mac.Sum(nil)
}

func ReadBytesWithLen(r io.Reader) ([]byte, error) {
	var l uint16
	if err := binary.Read(r, binary.BigEndian, &l); err != nil {
		return nil, err
	}
	if l == 0 {
		return nil, nil
	}
	buf := make([]byte, int(l))
	_, err := io.ReadFull(r, buf)
	return buf, err
}

func WriteBytesWithLen(w io.Writer, b []byte) error {
	if len(b) > 0xFFFF {
		return errors.New("message too long")
	}
	l := uint16(len(b))
	if err := binary.Write(w, binary.BigEndian, l); err != nil {
		return err
	}
	_, err := w.Write(b)
	return err
}
