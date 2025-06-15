package reality

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"sync"
	"time"

	"github.com/pires/go-proxyproto"
	utls "github.com/refraction-networking/utls"
)

var GlobalPostHandshakeRecordsLock sync.Mutex

var GlobalPostHandshakeRecordsLens map[string]map[string][]int

func InitAllRecords(config *Config) {
	DetectPostHandshakeRecordsLens(config, "hellochrome_131") // init most used first
	for f, _ := range ModernFingerprints {
		DetectPostHandshakeRecordsLens(config, f)
	}
}

func DetectPostHandshakeRecordsLens(config *Config, fingerprint string) map[string][]int {
	GlobalPostHandshakeRecordsLock.Lock()
	if GlobalPostHandshakeRecordsLens == nil {
		GlobalPostHandshakeRecordsLens = make(map[string]map[string][]int)
	}
	if GlobalPostHandshakeRecordsLens[fingerprint] == nil {
		GlobalPostHandshakeRecordsLens[fingerprint] = make(map[string][]int)
	}
	var pending []string
	for sni := range config.ServerNames {
		if (GlobalPostHandshakeRecordsLens[fingerprint][sni] == nil) {
			pending = append(pending, sni)
		}
	}
	GlobalPostHandshakeRecordsLock.Unlock()
	for _, sni := range pending {
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
			PostHandshakeRecordsLens: GlobalPostHandshakeRecordsLens[fingerprint],
			Sni:                      sni,
			Fingerprint:              fingerprint,
		}
		uConn := utls.UClient(detectConn, &utls.Config{
			ServerName: sni,
		}, *ModernFingerprints[fingerprint])
		if err = uConn.Handshake(); err != nil {
			continue
		}
		io.Copy(io.Discard, uConn)
	}
	return GlobalPostHandshakeRecordsLens[fingerprint]
}

type DetectConn struct {
	net.Conn
	PostHandshakeRecordsLens map[string][]int
	Sni                      string
	CcsSent                  bool
	Fingerprint              string
}

func (c *DetectConn) Write(b []byte) (n int, err error) {
	if len(b) >= 3 && bytes.Equal(b[:3], []byte{20, 3, 3}) {
		c.CcsSent = true
	}
	return c.Conn.Write(b)
}

func (c *DetectConn) Read(b []byte) (n int, err error) {
	if !c.CcsSent {
		c.Conn.SetReadDeadline(time.Now().Add(2 * time.Second))
		return c.Conn.Read(b)
	}
	c.Conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	data, _ := io.ReadAll(c.Conn)
	GlobalPostHandshakeRecordsLock.Lock()
	for {
		if len(data) >= 5 && bytes.Equal(data[:3], []byte{23, 3, 3}) {
			length := int(binary.BigEndian.Uint16(data[3:5])) + 5
			c.PostHandshakeRecordsLens[c.Sni] = append(c.PostHandshakeRecordsLens[c.Sni], length)
			data = data[length:]
		} else {
			break
		}
	}
	if len(c.PostHandshakeRecordsLens[c.Sni]) == 0 {
		c.PostHandshakeRecordsLens[c.Sni] = append(c.PostHandshakeRecordsLens[c.Sni], 0)
	}
	GlobalPostHandshakeRecordsLock.Unlock()
	fmt.Printf("REALITY fingerprint probe: %v\tSni: %v\tlen(postHandshakeRecord): %v\n", c.Fingerprint, c.Sni, c.PostHandshakeRecordsLens[c.Sni])
	return 0, io.EOF
}

var ModernFingerprints = map[string]*utls.ClientHelloID{
	// One of these will be chosen as `random` at startup
	"hellofirefox_99":         &utls.HelloFirefox_99,
	"hellofirefox_102":        &utls.HelloFirefox_102,
	"hellofirefox_105":        &utls.HelloFirefox_105,
	"hellofirefox_120":        &utls.HelloFirefox_120,
	"hellochrome_83":          &utls.HelloChrome_83,
	"hellochrome_87":          &utls.HelloChrome_87,
	"hellochrome_96":          &utls.HelloChrome_96,
	"hellochrome_100":         &utls.HelloChrome_100,
	"hellochrome_102":         &utls.HelloChrome_102,
	"hellochrome_106_shuffle": &utls.HelloChrome_106_Shuffle,
	"hellochrome_120":         &utls.HelloChrome_120,
	"hellochrome_131":         &utls.HelloChrome_131,
	"helloios_13":             &utls.HelloIOS_13,
	"helloios_14":             &utls.HelloIOS_14,
	"helloedge_85":            &utls.HelloEdge_85,
	"helloedge_106":           &utls.HelloEdge_106,
	"hellosafari_16_0":        &utls.HelloSafari_16_0,
	"hello360_11_0":           &utls.Hello360_11_0,
	"helloqq_11_1":            &utls.HelloQQ_11_1,

	"hellogolang":            &utls.HelloGolang,
	"hellorandomized":        &utls.HelloRandomized,
	"hellorandomizedalpn":    &utls.HelloRandomizedALPN,
	"hellorandomizednoalpn":  &utls.HelloRandomizedNoALPN,
}
