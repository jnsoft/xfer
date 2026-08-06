package client

import (
	"bytes"
	"errors"
	"io"
	"net"
	"testing"
)

type errorReader struct {
	err error
}

func (r errorReader) Read([]byte) (int, error) {
	return 0, r.err
}

func TestCopyServerOutput(t *testing.T) {
	tests := []struct {
		name       string
		input      io.Reader
		wantOutput string
		wantStatus string
	}{
		{
			name:       "clean close",
			input:      bytes.NewBufferString("reply\n"),
			wantOutput: "reply\n",
			wantStatus: "server closed connection\n",
		},
		{
			name:       "truncated compressed stream",
			input:      errorReader{err: io.ErrUnexpectedEOF},
			wantStatus: "server closed connection unexpectedly\n",
		},
		{
			name:       "closed connection",
			input:      errorReader{err: net.ErrClosed},
			wantStatus: "server closed connection\n",
		},
		{
			name:       "other read error",
			input:      errorReader{err: errors.New("read failed")},
			wantStatus: "receive error: read failed\n",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var output bytes.Buffer
			var diagnostics bytes.Buffer

			copyServerOutput(&output, test.input, &diagnostics)

			if got := output.String(); got != test.wantOutput {
				t.Fatalf("output = %q, want %q", got, test.wantOutput)
			}
			if got := diagnostics.String(); got != test.wantStatus {
				t.Fatalf("diagnostics = %q, want %q", got, test.wantStatus)
			}
		})
	}
}
