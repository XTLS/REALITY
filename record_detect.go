package reality

import (
	"bytes"
	"encoding/binary"
	"io"
	"net"
	"strconv"
	"sync"
	"time"

	"github.com/pires/go-proxyproto"
	utls "github.com/refraction-networking/utls"
)

var GlobalPostHandshakeRecordsLens sync.Map

func DetectPostHandshakeRecordsLens(config *Config) {
	for sni := range config.ServerNames {
		for alpn := range 3 { // 0, 1, 2
			key := config.Dest + " " + sni + " " + strconv.Itoa(alpn)
			if _, loaded := GlobalPostHandshakeRecordsLens.LoadOrStore(key, false); !loaded {
				go func() {
					defer func() {
						val, _ := GlobalPostHandshakeRecordsLens.Load(key)
						if _, ok := val.(bool); ok {
							GlobalPostHandshakeRecordsLens.Store(key, []int{})
						}
					}()
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
						Conn: target,
						Key:  key,
					}
					fingerprint := utls.HelloChrome_Auto
					nextProtos := []string{"h2", "http/1.1"}
					if alpn != 2 {
						fingerprint = utls.HelloGolang
					}
					if alpn == 1 {
						nextProtos = []string{"http/1.1"}
					}
					if alpn == 0 {
						nextProtos = nil
					}
					uConn := utls.UClient(detectConn, &utls.Config{
						ServerName: sni, // needs new loopvar behaviour
						NextProtos: nextProtos,
					}, fingerprint)
					if err = uConn.Handshake(); err != nil {
						return
					}
					io.Copy(io.Discard, uConn)
				}()
			}
		}
	}
}

type DetectConn struct {
	net.Conn
	Key     string
	CcsSent bool
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
	var postHandshakeRecordsLens []int
	for {
		if len(data) >= 5 && bytes.Equal(data[:3], []byte{23, 3, 3}) {
			length := int(binary.BigEndian.Uint16(data[3:5])) + 5
			postHandshakeRecordsLens = append(postHandshakeRecordsLens, length)
			data = data[length:]
		} else {
			break
		}
	}
	GlobalPostHandshakeRecordsLens.Store(c.Key, postHandshakeRecordsLens)
	return 0, io.EOF
}
