package reality

import (
	"bytes"
	"crypto/tls"
	"encoding/binary"
	"io"
	"net"
	"sync"
	"time"

	"github.com/pires/go-proxyproto"
)

var lock sync.Mutex

var PostHandshakeRecordsLen map[*Config]map[string][]int

func DetectPostHandshakeRecords(config *Config) {
	lock.Lock()
	if PostHandshakeRecordsLen == nil {
		PostHandshakeRecordsLen = make(map[*Config]map[string][]int)
	}
	if PostHandshakeRecordsLen[config] == nil {
		PostHandshakeRecordsLen[config] = make(map[string][]int)
		for sni := range config.ServerNames {
			target, err := net.Dial("tcp", config.Dest)
			if err != nil {
				return
			}
			if config.Xver == 1 || config.Xver == 2 {
				if _, err = proxyproto.HeaderProxyFromAddrs(config.Xver, target.LocalAddr(), target.RemoteAddr()).WriteTo(target); err != nil {
					return
				}
			}
			detectConn := &DetectConn{
				Conn:   target,
				config: config,
				sni:    sni,
			}
			tlsConn := tls.Client(detectConn, &tls.Config{
				ServerName: sni,
			})
			if err = tlsConn.Handshake(); err != nil {
				return
			}
			io.Copy(io.Discard, tlsConn)
		}
	}
	lock.Unlock()
}

type DetectConn struct {
	net.Conn
	config  *Config
	sni     string
	ccsSent bool
}

func (c *DetectConn) Write(b []byte) (n int, err error) {
	if len(b) >= 3 && bytes.Equal(b[:3], []byte{20, 3, 3}) {
		c.ccsSent = true
	}
	return c.Conn.Write(b)
}

func (c *DetectConn) Read(b []byte) (n int, err error) {
	if !c.ccsSent {
		return c.Conn.Read(b)
	}
	c.Conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	data, _ := io.ReadAll(c.Conn)
	for {
		if len(data) >= 5 && bytes.Equal(data[:3], []byte{23, 3, 3}) {
			length := int(binary.BigEndian.Uint16(data[3:5])) + 5
			PostHandshakeRecordsLen[c.config][c.sni] = append(PostHandshakeRecordsLen[c.config][c.sni], length)
			data = data[length:]
		} else {
			break
		}
	}
	return 0, io.EOF
}
