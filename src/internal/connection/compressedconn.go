package connection

import (
	"compress/gzip"
	"errors"
	"net"
	"sync"
	"time"
)

type CompressedConn struct {
	conn net.Conn
	rmu  sync.Mutex
	wmu  sync.Mutex
	zr   *gzip.Reader
	zw   *gzip.Writer
}

func WrapWithCompression(conn net.Conn) *CompressedConn {
	return &CompressedConn{
		conn: conn,
		zw:   gzip.NewWriter(conn),
	}
}

func (c *CompressedConn) Read(p []byte) (int, error) {
	c.rmu.Lock()
	defer c.rmu.Unlock()

	if c.zr == nil {
		reader, err := gzip.NewReader(c.conn)
		if err != nil {
			return 0, err
		}
		c.zr = reader
	}

	return c.zr.Read(p)
}

func (c *CompressedConn) Write(p []byte) (int, error) {
	c.wmu.Lock()
	defer c.wmu.Unlock()

	byteCount, err := c.zw.Write(p)
	if err != nil {
		return byteCount, err
	}

	if err := c.zw.Flush(); err != nil {
		return byteCount, err
	}

	return byteCount, nil
}

func (c *CompressedConn) CloseWrite() error {
	c.wmu.Lock()
	defer c.wmu.Unlock()

	if err := c.zw.Close(); err != nil {
		return err
	}

	if conn, ok := c.conn.(interface{ CloseWrite() error }); ok {
		return conn.CloseWrite()
	}

	return errors.New("underlying connection does not support CloseWrite")
}

func (c *CompressedConn) Close() error {
	c.wmu.Lock()
	defer c.wmu.Unlock()

	if err := c.zw.Close(); err != nil {
		_ = c.conn.Close()
		return err
	}

	return c.conn.Close()
}

func (c *CompressedConn) LocalAddr() net.Addr                { return c.conn.LocalAddr() }
func (c *CompressedConn) RemoteAddr() net.Addr               { return c.conn.RemoteAddr() }
func (c *CompressedConn) SetDeadline(t time.Time) error      { return c.conn.SetDeadline(t) }
func (c *CompressedConn) SetReadDeadline(t time.Time) error  { return c.conn.SetReadDeadline(t) }
func (c *CompressedConn) SetWriteDeadline(t time.Time) error { return c.conn.SetWriteDeadline(t) }
