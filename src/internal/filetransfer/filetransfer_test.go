package filetransfer

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"math"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestSendReceiveRoundTrip(t *testing.T) {
	tempDir := t.TempDir()
	sourcePath := filepath.Join(tempDir, "source.bin")
	destinationPath := filepath.Join(tempDir, "received.bin")
	content := bytes.Repeat([]byte("xfer-data-"), 4096)

	if err := os.WriteFile(sourcePath, content, 0o600); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}

	sender, receiver := net.Pipe()
	defer sender.Close()

	receiveDone := make(chan error, 1)
	go func() {
		defer receiver.Close()
		receiveDone <- Receive(receiver, destinationPath)
	}()

	if err := Send(sender, sourcePath); err != nil {
		t.Fatalf("Send() error = %v", err)
	}

	if err := waitForResult(t, receiveDone); err != nil {
		t.Fatalf("Receive() error = %v", err)
	}

	received, err := os.ReadFile(destinationPath)
	if err != nil {
		t.Fatalf("ReadFile() error = %v", err)
	}
	if !bytes.Equal(received, content) {
		t.Fatal("received file differs from source")
	}
}

func TestReceiveRejectsTruncatedPayloadAndRemovesTemporaryFile(t *testing.T) {
	tempDir := t.TempDir()
	destinationPath := filepath.Join(tempDir, "received.bin")
	sender, receiver := net.Pipe()

	receiveDone := make(chan error, 1)
	go func() {
		defer receiver.Close()
		receiveDone <- Receive(receiver, destinationPath)
	}()

	if err := writeHeader(sender, Header{
		Name: "source.bin",
		Size: 10,
	}); err != nil {
		t.Fatalf("writeHeader() error = %v", err)
	}
	if _, err := sender.Write([]byte("short")); err != nil {
		t.Fatalf("Write() error = %v", err)
	}
	_ = sender.Close()

	if err := waitForResult(t, receiveDone); err == nil {
		t.Fatal("Receive() error = nil, want truncated payload error")
	}

	assertNoDestinationOrTemporaryFile(t, destinationPath)
}

func TestReceiveRejectsChecksumMismatchAndRemovesTemporaryFile(t *testing.T) {
	tempDir := t.TempDir()
	destinationPath := filepath.Join(tempDir, "received.bin")
	content := []byte("file content")
	sender, receiver := net.Pipe()

	receiveDone := make(chan error, 1)
	go func() {
		defer receiver.Close()
		receiveDone <- Receive(receiver, destinationPath)
	}()

	var wrongDigest [sha256.Size]byte
	copy(wrongDigest[:], []byte("not-the-right-digest"))

	if err := writeHeader(sender, Header{
		Name:   "source.bin",
		Size:   uint64(len(content)),
		SHA256: wrongDigest,
	}); err != nil {
		t.Fatalf("writeHeader() error = %v", err)
	}
	if _, err := sender.Write(content); err != nil {
		t.Fatalf("Write() error = %v", err)
	}
	_ = sender.Close()

	if err := waitForResult(t, receiveDone); !errors.Is(err, ErrChecksum) {
		t.Fatalf("Receive() error = %v, want ErrChecksum", err)
	}

	assertNoDestinationOrTemporaryFile(t, destinationPath)
}

func TestReadHeaderRejectsSizeAboveMaxInt64(t *testing.T) {
	var encoded bytes.Buffer
	if err := writeHeader(&encoded, Header{
		Name: "source.bin",
		Size: uint64(math.MaxInt64) + 1,
	}); err != nil {
		t.Fatalf("writeHeader() error = %v", err)
	}

	_, err := readHeader(&encoded)
	if !errors.Is(err, ErrInvalidHeader) {
		t.Fatalf("readHeader() error = %v, want ErrInvalidHeader", err)
	}
}

func TestReadHeaderRejectsInvalidMagic(t *testing.T) {
	header := make([]byte, headerFixedSize)
	copy(header[:8], "BADMAGIC")
	header[8] = version
	header[9] = 1

	_, err := readHeader(bytes.NewReader(header))
	if !errors.Is(err, ErrInvalidHeader) {
		t.Fatalf("readHeader() error = %v, want ErrInvalidHeader", err)
	}
}

func TestSendRejectsMissingAndNonRegularSource(t *testing.T) {
	tempDir := t.TempDir()

	if err := Send(nil, filepath.Join(tempDir, "missing.bin")); err == nil {
		t.Fatal("Send() missing source error = nil")
	}
	if err := Send(nil, tempDir); err == nil {
		t.Fatal("Send() directory source error = nil")
	}
}

func waitForResult(t *testing.T, result <-chan error) error {
	t.Helper()

	select {
	case err := <-result:
		return err
	case <-time.After(time.Second):
		t.Fatal("operation did not complete")
		return nil
	}
}

func assertNoDestinationOrTemporaryFile(t *testing.T, destinationPath string) {
	t.Helper()

	if _, err := os.Stat(destinationPath); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("destination stat error = %v, want not exist", err)
	}

	temporaryFiles, err := filepath.Glob(
		filepath.Join(
			filepath.Dir(destinationPath),
			"."+filepath.Base(destinationPath)+".part-*",
		),
	)
	if err != nil {
		t.Fatalf("Glob() error = %v", err)
	}
	if len(temporaryFiles) != 0 {
		t.Fatalf("temporary files = %v, want none", temporaryFiles)
	}
}
