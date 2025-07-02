package reality

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"slices"
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
		if GlobalPostHandshakeRecordsLens[fingerprint][sni] == nil {
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
	c.Conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	if !c.CcsSent {
		return c.Conn.Read(b)
	}
	data, _ := io.ReadAll(c.Conn)
	var newLength []int
	for {
		if len(data) >= 5 && bytes.Equal(data[:3], []byte{23, 3, 3}) {
			length := int(binary.BigEndian.Uint16(data[3:5])) + 5
			newLength = append(newLength, length)
			data = data[length:]
		} else {
			break
		}
	}
	GlobalPostHandshakeRecordsLock.Lock()
	if len(newLength) == 0 {
		c.PostHandshakeRecordsLens[c.Sni] = append(c.PostHandshakeRecordsLens[c.Sni], 0)
	} else {
		c.PostHandshakeRecordsLens[c.Sni] = newLength
	}
	GlobalPostHandshakeRecordsLock.Unlock()
	fmt.Printf("REALITY fingerprint probe: %v\tSni: %v\tlen(postHandshakeRecord): %v\n", c.Fingerprint, c.Sni, c.PostHandshakeRecordsLens[c.Sni])
	return 0, io.EOF
}

func IdentifyModernFingerprint(ch *clientHelloMsg) string {
	if slices.Contains(ch.cipherSuites, DISABLED_TLS_RSA_WITH_AES_256_CBC_SHA256) {
		if slices.Contains(ch.cipherSuites, GREASE_PLACEHOLDER) {
			return "helloios_14"
		}
		return "helloios_13"
	}
	if slices.Contains(ch.cipherSuites, FAKE_TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA) {
		return "hellosafari_16_0"
	}
	if slices.Contains(ch.extensions, fakeRecordSizeLimit) {
		if slices.Contains(ch.supportedVersions, VersionTLS10) && slices.Contains(ch.supportedVersions, VersionTLS11) {
			return "hellofirefox_99"
		}
		if !slices.Contains(ch.alpnProtocols, "http/1.1") {
			return "hellofirefox_102"
		}
		if slices.Contains(ch.extensions, utlsExtensionECH) {
			return "hellofirefox_120"
		}
		if slices.Contains(ch.extensions, utlsExtensionPadding) {
			return "hellofirefox_105"
		}
	}
	if slices.Contains(ch.supportedVersions, VersionTLS10) && slices.Contains(ch.supportedVersions, VersionTLS11) {
		if slices.Contains(ch.extensions, fakeExtensionChannelID) {
			return "hello360_11_0"
		}
		if slices.Contains(ch.extensions, utlsExtensionApplicationSettings) {
			return "hellochrome_96" // also helloqq_11_1
		}
		return "hellochrome_87" // also hellochrome_83, helloedge_85
	}
	if slices.Contains(ch.supportedCurves, X25519MLKEM768) {
		if slices.Contains(ch.extensions, utlsExtensionApplicationSettingsNew) {
			return "hellochrome_133"
		}
		return "hellochrome_131"
	}
	if slices.Contains(ch.extensions, utlsExtensionECH) {
		return "hellochrome_120"
	}
	if slices.Contains(ch.extensions, utlsExtensionPadding) {
		return "hellochrome_106_shuffle" // also HelloChrome_100, HelloChrome_102, helloedge_106
	}
	return "Custom"
}

const (
	utlsExtensionPadding                uint16 = 21
	utlsExtensionApplicationSettings    uint16 = 17513  // not IANA assigned
	utlsExtensionApplicationSettingsNew uint16 = 17613  // not IANA assigned
	utlsExtensionECH                    uint16 = 0xfe0d // draft-ietf-tls-esni-17

	fakeRecordSizeLimit    uint16 = 0x001c
	fakeExtensionChannelID uint16 = 30032 // not IANA assigned

	DISABLED_TLS_RSA_WITH_AES_256_CBC_SHA256   = uint16(0x003d)
	FAKE_TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA = uint16(0xc008) // https://docs.microsoft.com/en-us/dotnet/api/system.net.security.tlsciphersuite?view=netcore-3.1

	// based on spec's GreaseStyle, GREASE_PLACEHOLDER may be replaced by another GREASE value
	// https://tools.ietf.org/html/draft-ietf-tls-grease-01
	GREASE_PLACEHOLDER = 0x0a0a
)

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
