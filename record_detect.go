package reality

import (
	"bytes"
	"encoding/binary"
	"io"
	"net"
	"sync"
	"time"

	"github.com/pires/go-proxyproto"
	utls "github.com/refraction-networking/utls"
)

var GlobalPostHandshakeRecordsLock sync.Mutex

var GlobalPostHandshakeRecordsLens map[*Config]map[string][]int

func DetectPostHandshakeRecordsLens(config *Config) map[string][]int {
	GlobalPostHandshakeRecordsLock.Lock()
	defer GlobalPostHandshakeRecordsLock.Unlock()
	if GlobalPostHandshakeRecordsLens == nil {
		GlobalPostHandshakeRecordsLens = make(map[*Config]map[string][]int)
	}
	if GlobalPostHandshakeRecordsLens[config] == nil {
		GlobalPostHandshakeRecordsLens[config] = make(map[string][]int)
		for sni := range config.ServerNames {
			target, err := net.Dial("tcp", config.Dest)
			if err != nil {
				continue
			}
			if config.Xver == 1 || config.Xver == 2 {
				if _, err = proxyproto.HeaderProxyFromAddrs(config.Xver, target.LocalAddr(), target.RemoteAddr()).WriteTo(target); err != nil {
					continue
				}
			}
			detectConn := &DetectConn{
				Conn:                     target,
				PostHandshakeRecordsLens: GlobalPostHandshakeRecordsLens[config],
				Sni:                      sni,
			}
			uConn := utls.UClient(detectConn, &utls.Config{
				ServerName: sni,
			}, utls.HelloChrome_Auto)
			if err = uConn.Handshake(); err != nil {
				continue
			}
			io.Copy(io.Discard, uConn)
		}
	}
	return GlobalPostHandshakeRecordsLens[config]
}

type DetectConn struct {
	net.Conn
	PostHandshakeRecordsLens map[string][]int
	Sni                      string
	CcsSent                  bool
}

func (c *DetectConn) Write(b []byte) (n int, err error) {
	if len(b) >= 3 && bytes.Equal(b[:3], []byte{20, 3, 3}) {
		c.CcsSent = true
	}
	return c.Conn.Write(b)
}

func (c *DetectConn) Read(b []byte) (n int, err error) {
	if !c.CcsSent {
		return c.Conn.Read(b)
	}
	c.Conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	data, _ := io.ReadAll(c.Conn)
	for {
		if len(data) >= 5 && bytes.Equal(data[:3], []byte{23, 3, 3}) {
			length := int(binary.BigEndian.Uint16(data[3:5])) + 5
			c.PostHandshakeRecordsLens[c.Sni] = append(c.PostHandshakeRecordsLens[c.Sni], length)
			data = data[length:]
		} else {
			break
		}
	}
	return 0, io.EOF
}
