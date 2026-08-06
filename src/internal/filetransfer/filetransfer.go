package filetransfer

import (
    "crypto/sha256"
    "encoding/binary"
    "errors"
    "fmt"
    "io"
    "net"
    "os"
    "path/filepath"
)

const (
    version         = 1
    maxNameLength   = 4096
    headerFixedSize = 8 + 1 + 2 + 8 + sha256.Size
    ackMagic        = "XFERACK1"
)

var (
    fileMagic = [8]byte{'X', 'F', 'E', 'R', 'F', 'I', 'L', 'E'}

    ErrInvalidHeader = errors.New("invalid file-transfer header")
    ErrChecksum      = errors.New("file checksum mismatch")
)

type Header struct {
    Name   string
    Size   uint64
    SHA256 [sha256.Size]byte
}

func Send(conn net.Conn, sourcePath string) error {
    header, err := sourceHeader(sourcePath)
    if err != nil {
        return err
    }
    if err := writeHeader(conn, header); err != nil {
        return fmt.Errorf("send file header: %w", err)
    }

    source, err := os.Open(sourcePath)
    if err != nil {
        return fmt.Errorf("open source file: %w", err)
    }
    defer source.Close()

    if written, err := io.Copy(conn, source); err != nil {
        return fmt.Errorf("send file data: %w", err)
    } else if uint64(written) != header.Size {
        return io.ErrShortWrite
    }

    if err := readAck(conn); err != nil {
        return fmt.Errorf("receiver rejected file: %w", err)
    }
    return nil
}

func Receive(conn net.Conn, destinationPath string) error {
    header, err := readHeader(conn)
    if err != nil {
        return err
    }

    destinationDir := filepath.Dir(destinationPath)
    temporary, err := os.CreateTemp(destinationDir, "."+filepath.Base(destinationPath)+".part-*")
    if err != nil {
        return fmt.Errorf("create temporary destination: %w", err)
    }
    temporaryPath := temporary.Name()
    success := false
    defer func() {
        _ = temporary.Close()
        if !success {
            _ = os.Remove(temporaryPath)
        }
    }()

    hasher := sha256.New()
    writer := io.MultiWriter(temporary, hasher)
    written, err := io.CopyN(writer, conn, int64(header.Size))
    if err != nil {
        _ = writeAck(conn, err)
        return fmt.Errorf("receive file data: %w", err)
    }
    if uint64(written) != header.Size {
        _ = writeAck(conn, io.ErrUnexpectedEOF)
        return io.ErrUnexpectedEOF
    }

    var receivedHash [sha256.Size]byte
    copy(receivedHash[:], hasher.Sum(nil))
    if receivedHash != header.SHA256 {
        _ = writeAck(conn, ErrChecksum)
        return ErrChecksum
    }

    if err := temporary.Close(); err != nil {
        _ = writeAck(conn, err)
        return fmt.Errorf("close temporary destination: %w", err)
    }
    if err := os.Rename(temporaryPath, destinationPath); err != nil {
        _ = writeAck(conn, err)
        return fmt.Errorf("finalize destination: %w", err)
    }

    success = true
    if err := writeAck(conn, nil); err != nil {
        return fmt.Errorf("send completion acknowledgement: %w", err)
    }
    return nil
}

func sourceHeader(sourcePath string) (Header, error) {
    source, err := os.Open(sourcePath)
    if err != nil {
        return Header{}, fmt.Errorf("open source file: %w", err)
    }
    defer source.Close()

    info, err := source.Stat()
    if err != nil {
        return Header{}, fmt.Errorf("stat source file: %w", err)
    }
    if !info.Mode().IsRegular() {
        return Header{}, errors.New("source must be a regular file")
    }

    name := filepath.Base(sourcePath)
    if len(name) == 0 || len(name) > maxNameLength {
        return Header{}, errors.New("source filename is invalid")
    }

    hasher := sha256.New()
    if _, err := io.Copy(hasher, source); err != nil {
        return Header{}, fmt.Errorf("hash source file: %w", err)
    }

    var digest [sha256.Size]byte
    copy(digest[:], hasher.Sum(nil))
    return Header{Name: name, Size: uint64(info.Size()), SHA256: digest}, nil
}

func writeHeader(writer io.Writer, header Header) error {
    if len(header.Name) == 0 || len(header.Name) > maxNameLength {
        return ErrInvalidHeader
    }

    message := make([]byte, headerFixedSize+len(header.Name))
    copy(message[:8], fileMagic[:])
    message[8] = version
    binary.BigEndian.PutUint16(message[9:11], uint16(len(header.Name)))
    binary.BigEndian.PutUint64(message[11:19], header.Size)
    copy(message[19:51], header.SHA256[:])
    copy(message[51:], header.Name)
    _, err := writer.Write(message)
    return err
}

func readHeader(reader io.Reader) (Header, error) {
    var fixed [headerFixedSize]byte
    if _, err := io.ReadFull(reader, fixed[:]); err != nil {
        return Header{}, fmt.Errorf("read file header: %w", err)
    }
    if string(fixed[:8]) != string(fileMagic[:]) || fixed[8] != version {
        return Header{}, ErrInvalidHeader
    }

    nameLength := int(binary.BigEndian.Uint16(fixed[9:11]))
    if nameLength == 0 || nameLength > maxNameLength {
        return Header{}, ErrInvalidHeader
    }

    name := make([]byte, nameLength)
    if _, err := io.ReadFull(reader, name); err != nil {
        return Header{}, fmt.Errorf("read file name: %w", err)
    }

    var digest [sha256.Size]byte
    copy(digest[:], fixed[19:51])
    return Header{
        Name:   string(name),
        Size:   binary.BigEndian.Uint64(fixed[11:19]),
        SHA256: digest,
    }, nil
}

func writeAck(writer io.Writer, transferErr error) error {
    status := byte(0)
    message := ""
    if transferErr != nil {
        status = 1
        message = transferErr.Error()
    }
    if len(message) > maxNameLength {
        message = message[:maxNameLength]
    }

    ack := make([]byte, 8+1+2+len(message))
    copy(ack[:8], ackMagic)
    ack[8] = status
    binary.BigEndian.PutUint16(ack[9:11], uint16(len(message)))
    copy(ack[11:], message)
    _, err := writer.Write(ack)
    return err
}

func readAck(reader io.Reader) error {
    var fixed [11]byte
    if _, err := io.ReadFull(reader, fixed[:]); err != nil {
        return fmt.Errorf("read completion acknowledgement: %w", err)
    }
    if string(fixed[:8]) != ackMagic {
        return errors.New("invalid file-transfer acknowledgement")
    }

    messageLength := int(binary.BigEndian.Uint16(fixed[9:11]))
    if messageLength > maxNameLength {
        return errors.New("invalid acknowledgement length")
    }
    message := make([]byte, messageLength)
    if _, err := io.ReadFull(reader, message); err != nil {
        return fmt.Errorf("read acknowledgement message: %w", err)
    }
    if fixed[8] != 0 {
        return errors.New(string(message))
    }
    return nil
}