package reality

import (
	"bytes"
	"crypto/tls"
	"encoding/binary"
	"io"
	"net"
	"time"
)

func DetectRecordFingerprint(target string) ([]int, error) {
	NetConn, err := net.Dial("tcp", target)
	if err != nil {
		return nil, err
	}
	conn := &detectConn{
		Conn:       NetConn,
		resultChan: make(chan []int, 1),
	}
	host, _, err := net.SplitHostPort(target)
	if err != nil {
		return nil, err
	}
	tlsConfig := &tls.Config{
		ServerName: host,
	}
	tlsConn := tls.Client(conn, tlsConfig)
	if err != nil {
		return nil, err
	}
	go func() {
		io.Copy(io.Discard, tlsConn)
	}()
	select {
	case result := <-conn.resultChan:
		return result, nil
	case <-time.After(2 * time.Second):
		return nil, nil
	}
}

type detectConn struct {
	net.Conn
	ccsSent    bool
	done       bool
	resultChan chan ([]int)
}

func (c *detectConn) Write(b []byte) (n int, err error) {
	if len(b) >= 3 && bytes.Equal(b[:3], []byte{20, 3, 3}) {
		c.ccsSent = true
	}
	return c.Conn.Write(b)
}

func (c *detectConn) Read(b []byte) (n int, err error) {
	n, err = c.Conn.Read(b)
	if c.ccsSent && !c.done {
		data := make([]byte, len(b))
		copy(data, b)
		var result []int
		for {
			if len(data) > 3 && bytes.Equal(data[:3], []byte{23, 3, 3}) {
				length := int(binary.BigEndian.Uint16(data[3:5]))
				if len(data) > length+5 {
					result = append(result, int(length))
					data = data[length+5:]
				}
			} else {
				break
			}
		}
		if len(result) != 1 {
		c.done = true
		c.resultChan <- result
		}
	}
	return n, err
}
