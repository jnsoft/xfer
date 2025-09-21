package connection

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"sync"
	"time"
)

type SecureConn struct {
	conn net.Conn
	aead cipher.AEAD
	rbuf bytes.Buffer
	rmu  sync.Mutex
	wmu  sync.Mutex
}

func (s *SecureConn) Close() error {
	return s.conn.Close()
}

func (s *SecureConn) LocalAddr() net.Addr                { return s.conn.LocalAddr() }
func (s *SecureConn) RemoteAddr() net.Addr               { return s.conn.RemoteAddr() }
func (s *SecureConn) SetDeadline(t time.Time) error      { return s.conn.SetDeadline(t) }
func (s *SecureConn) SetReadDeadline(t time.Time) error  { return s.conn.SetReadDeadline(t) }
func (s *SecureConn) SetWriteDeadline(t time.Time) error { return s.conn.SetWriteDeadline(t) }

// WrapWithAE performs an ECDH handshake (P-256) and returns a SecureConn.
// isServer controls handshake ordering: server reads peer pubkey first, client writes first.
// authKey is an optional pre-shared key string used to authenticate the handshake (mitm protection).
func WrapWithAE(conn net.Conn, isServer bool, authKey string) (*SecureConn, error) {
	aead, err := performECDHHandshake(conn, isServer, authKey)
	if err != nil {
		return nil, err
	}
	return &SecureConn{conn: conn, aead: aead}, nil
}

func performECDHHandshake(conn net.Conn, isServer bool, authKey string) (cipher.AEAD, error) {
	curve := elliptic.P256()

	// generate our private/public
	priv, x, y, err := elliptic.GenerateKey(curve, rand.Reader)
	if err != nil {
		return nil, err
	}
	pub := elliptic.Marshal(curve, x, y) // 65 bytes (0x04|X|Y)

	var peerPub []byte
	if isServer {
		// server reads peer pubkey first, then sends its pubkey
		peerPub, err = readBytesWithLen(conn)
		if err != nil {
			return nil, err
		}
		if err := writeBytesWithLen(conn, pub); err != nil {
			return nil, err
		}
	} else {
		// client writes first, then reads
		if err := writeBytesWithLen(conn, pub); err != nil {
			return nil, err
		}
		peerPub, err = readBytesWithLen(conn)
		if err != nil {
			return nil, err
		}
	}

	px, py := elliptic.Unmarshal(curve, peerPub)
	if px == nil {
		return nil, errors.New("invalid peer public key")
	}

	// shared secret: x-coordinate of scalar mult
	sx, _ := curve.ScalarMult(px, py, priv)
	shared := sx.Bytes()

	// if authKey provided, perform an authentication exchange to prevent MITM.
	// client sends auth first, server reads and verifies then responds.
	if authKey != "" {
		auth := computeAuth([]byte(authKey), shared)
		if isServer {
			// server: read client's auth, verify, then send its auth
			peerAuth, err := readBytesWithLen(conn)
			if err != nil {
				return nil, err
			}
			if !hmac.Equal(peerAuth, auth) {
				return nil, errors.New("handshake authentication failed")
			}
			if err := writeBytesWithLen(conn, auth); err != nil {
				return nil, err
			}
		} else {
			// client: send auth, read server's auth and verify
			if err := writeBytesWithLen(conn, auth); err != nil {
				return nil, err
			}
			peerAuth, err := readBytesWithLen(conn)
			if err != nil {
				return nil, err
			}
			if !hmac.Equal(peerAuth, auth) {
				return nil, errors.New("handshake authentication failed")
			}
		}
	}

	// derive 32-byte key via SHA-256(shared)
	key := sha256.Sum256(shared)

	block, err := aes.NewCipher(key[:])
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	return aead, nil
}

func computeAuth(psk, shared []byte) []byte {
	mac := hmac.New(sha256.New, psk)
	mac.Write(shared)
	return mac.Sum(nil)
}

func computeAuth(psk, shared []byte) []byte {
	mac := hmac.New(sha256.New, psk)
	mac.Write(shared)
	return mac.Sum(nil)
}

func readBytesWithLen(r io.Reader) ([]byte, error) {
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

func writeBytesWithLen(w io.Writer, b []byte) error {
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

// Read implements io.Reader: reads one framed encrypted record, decrypts and serves data.
func (s *SecureConn) Read(p []byte) (int, error) {
	s.rmu.Lock()
	defer s.rmu.Unlock()

	// if buffer has data, serve it
	if s.rbuf.Len() > 0 {
		return s.rbuf.Read(p)
	}

	// read 4-byte length
	var l uint32
	if err := binary.Read(s.conn, binary.BigEndian, &l); err != nil {
		return 0, err
	}
	if l < uint32(s.aead.NonceSize()) {
		return 0, errors.New("invalid frame")
	}
	frame := make([]byte, int(l))
	if _, err := io.ReadFull(s.conn, frame); err != nil {
		return 0, err
	}
	nonce := frame[:s.aead.NonceSize()]
	ct := frame[s.aead.NonceSize():]

	plain, err := s.aead.Open(nil, nonce, ct, nil)
	if err != nil {
		return 0, err
	}

	s.rbuf.Write(plain)
	return s.rbuf.Read(p)
}

// Write encrypts and writes framed records. It returns len(p) on success.
func (s *SecureConn) Write(p []byte) (int, error) {
	s.wmu.Lock()
	defer s.wmu.Unlock()

	const maxChunk = 32 * 1024 // 32KB plaintext per frame
	total := 0
	for len(p) > 0 {
		chunk := p
		if len(chunk) > maxChunk {
			chunk = chunk[:maxChunk]
		}
		nonce := make([]byte, s.aead.NonceSize())
		if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
			return total, err
		}
		ct := s.aead.Seal(nil, nonce, chunk, nil)
		frameLen := uint32(len(nonce) + len(ct))

		var hdr [4]byte
		binary.BigEndian.PutUint32(hdr[:], frameLen)

		buf := make([]byte, 4+len(nonce)+len(ct))
		copy(buf[0:4], hdr[:])
		copy(buf[4:4+len(nonce)], nonce)
		copy(buf[4+len(nonce):], ct)

		if _, err := s.conn.Write(buf); err != nil {
			return total, err
		}

		total += len(chunk)
		p = p[len(chunk):]
	}
	return total, nil
}

// CloseWrite attempts to close only the write side if underlying connection supports it.
func (s *SecureConn) CloseWrite() error {
	if tcp, ok := s.conn.(interface{ CloseWrite() error }); ok {
		return tcp.CloseWrite()
	}
	return errors.New("underlying conn does not support CloseWrite")
}
