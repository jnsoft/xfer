package connection

import (
	"errors"
	"fmt"
	"io"
	"net"
)

const (
	helloVersion   = 1
	helloSize      = 8
	capCompression = 1 << 0
)

var (
	ErrProtocolVersion     = errors.New("unsupported protocol version")
	ErrCompressionMismatch = errors.New("compression setting does not match peer")
)

type hello struct {
	version uint8
	flags   uint8
}

func NegotiateCapabilities(conn net.Conn, isServer, compress bool) (bool, error) {
	local := hello{
		version: helloVersion,
	}
	if compress {
		local.flags |= capCompression
	}

	var peer hello
	var err error
	if isServer {
		peer, err = readHello(conn)
		if err == nil {
			err = writeHello(conn, local)
		}
	} else {
		if err = writeHello(conn, local); err == nil {
			peer, err = readHello(conn)
		}
	}
	if err != nil {
		return false, err
	}

	if peer.version != helloVersion {
		return false, fmt.Errorf("%w: peer version %d", ErrProtocolVersion, peer.version)
	}

	peerCompression := peer.flags&capCompression != 0
	if peerCompression != compress {
		return false, ErrCompressionMismatch
	}

	return compress, nil
}

func writeHello(conn net.Conn, value hello) error {
	var message [helloSize]byte
	copy(message[:4], "XFR2")
	message[4] = value.version
	message[5] = value.flags

	return writeFull(conn, message[:])
}

func readHello(conn net.Conn) (hello, error) {
	var message [helloSize]byte
	if _, err := io.ReadFull(conn, message[:]); err != nil {
		return hello{}, fmt.Errorf("read protocol hello: %w", err)
	}
	if string(message[:4]) != "XFR2" {
		return hello{}, errors.New("invalid protocol hello")
	}

	return hello{
		version: message[4],
		flags:   message[5],
	}, nil
}

func writeFull(writer io.Writer, data []byte) error {
	for len(data) > 0 {
		count, err := writer.Write(data)
		if err != nil {
			return err
		}
		if count == 0 {
			return io.ErrShortWrite
		}
		data = data[count:]
	}
	return nil
}
