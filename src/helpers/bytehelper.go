package helpers

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"io"
)

func ComputeAuth(psk, shared []byte) []byte {
	mac := hmac.New(sha256.New, psk)
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
