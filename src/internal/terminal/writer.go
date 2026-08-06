package terminal

import (
    "fmt"
    "io"
    "sync"
)

type Writer struct {
    mu     sync.Mutex
    writer io.Writer
}

func NewWriter(writer io.Writer) *Writer {
    return &Writer{writer: writer}
}

func (w *Writer) Write(data []byte) (int, error) {
    w.mu.Lock()
    defer w.mu.Unlock()

    for _, value := range data {
        if value == '\n' || value == '\r' || value == '\t' ||
            (value >= 0x20 && value <= 0x7e) {
            if _, err := w.writer.Write([]byte{value}); err != nil {
                return 0, err
            }
            continue
        }

        if _, err := fmt.Fprintf(w.writer, "\\x%02X", value); err != nil {
            return 0, err
        }
    }

    return len(data), nil
}