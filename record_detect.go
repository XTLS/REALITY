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

var GlobalPostHandshakeRecordsLens map[*Config]map[string][]TrafficPacket

func DetectPostHandshakeRecordsLens(config *Config) map[string][]TrafficPacket {
	GlobalPostHandshakeRecordsLock.Lock()
	defer GlobalPostHandshakeRecordsLock.Unlock()
	if GlobalPostHandshakeRecordsLens == nil {
		GlobalPostHandshakeRecordsLens = make(map[*Config]map[string][]TrafficPacket)
	}
	if GlobalPostHandshakeRecordsLens[config] == nil {
		GlobalPostHandshakeRecordsLens[config] = make(map[string][]TrafficPacket)
		for sni := range config.ServerNames {
			var tcpStart = time.Now()
			target, err := net.Dial("tcp", config.Dest)
			var tcpDone = time.Now()
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
				TcpStart:                 tcpStart,
				TcpDone:                  tcpDone,
			}
			uConn := utls.UClient(detectConn, &utls.Config{
				ServerName: sni,
			}, utls.HelloChrome_Auto)
			detectConn.HandshakeStart = time.Now()
			if err = uConn.Handshake(); err != nil {
				continue
			}
			detectConn.HandshakeDone = time.Now()
			io.Copy(io.Discard, uConn)
		}
	}
	return GlobalPostHandshakeRecordsLens[config]
}

type TrafficPacket struct {
	Direction      bool
	Lens           []int
	SinceHandshake time.Duration
}

type DetectConn struct {
	net.Conn
	PostHandshakeRecordsLens map[string][]TrafficPacket
	Sni                      string
	CcsSent                  bool

	TcpStart       time.Time
	TcpDone        time.Time
	HandshakeStart time.Time
	HandshakeDone  time.Time
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
	for {
		data := make([]byte, 0, 2048)
		n, err = c.Conn.Read(data[len(data):cap(data)])
		data = data[:len(data)+n]
		if err != nil {
			return 0, err
		}
		newPacket := TrafficPacket {
			SinceHandshake: time.Since(c.HandshakeDone),
		}
		for len(data) > 0 {
			if len(data) >= 5 && bytes.Equal(data[:3], []byte{23, 3, 3}) {
				length := int(binary.BigEndian.Uint16(data[3:5])) + 5
				newPacket.Lens = append(newPacket.Lens, length)
				data = data[length:]
			} else {
				break
			}
		}
		c.PostHandshakeRecordsLens[c.Sni] = append(c.PostHandshakeRecordsLens[c.Sni], newPacket)
	}
}
