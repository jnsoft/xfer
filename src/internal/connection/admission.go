package connection

import (
	"bufio"
	"errors"
	"fmt"
	"net"
	"time"
)

var ErrServerBusy = errors.New("server is already connected")

const (
	admissionAccepted = "XFER/1 OK\n"
	admissionBusy     = "XFER/1 BUSY\n"
)

func SendAdmission(conn net.Conn, accepted bool) error {
	if accepted {
		_, err := fmt.Fprint(conn, admissionAccepted)
		return err
	}

	_, err := fmt.Fprint(conn, admissionBusy)
	return err
}

func ReadAdmission(conn net.Conn) error {
	if err := conn.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
		return err
	}
	defer conn.SetReadDeadline(time.Time{})

	status, err := bufio.NewReader(conn).ReadString('\n')
	if err != nil {
		return fmt.Errorf("read server admission: %w", err)
	}

	switch status {
	case admissionAccepted:
		return nil
	case admissionBusy:
		return ErrServerBusy
	default:
		return fmt.Errorf("invalid server admission response %q", status)
	}
}
