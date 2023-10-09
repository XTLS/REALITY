// Copyright 2009 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE-Go file.

// Server side implementation of REALITY protocol, a fork of package tls in Go 1.20.
// For client side, please follow https://github.com/XTLS/Xray-core/blob/main/transport/internet/reality/reality.go.
package reality

// BUG(agl): The crypto/tls package only implements some countermeasures
// against Lucky13 attacks on CBC-mode encryption, and only on SHA1
// variants. See http://www.isg.rhul.ac.uk/tls/TLStiming.pdf and
// https://www.imperialviolet.org/2013/02/04/luckythirteen.html.

import (
	"bytes"
	"context"
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/binary"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/pires/go-proxyproto"
	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/hkdf"
)

type MirrorConn struct {
	*sync.Mutex
	net.Conn
	Target net.Conn
}

func (c *MirrorConn) Read(b []byte) (int, error) {
	c.Unlock()
	runtime.Gosched()
	n, err := c.Conn.Read(b)
	c.Lock() // calling c.Lock() before c.Target.Write(), to make sure that this goroutine has the priority to make the next move
	if n != 0 {
		c.Target.Write(b[:n])
	}
	if err != nil {
		c.Target.Close()
	}
	return n, err
}

func (c *MirrorConn) Write(b []byte) (int, error) {
	return 0, fmt.Errorf("Write(%v)", len(b))
}

func (c *MirrorConn) Close() error {
	return fmt.Errorf("Close()")
}

func (c *MirrorConn) SetDeadline(t time.Time) error {
	return nil
}

func (c *MirrorConn) SetReadDeadline(t time.Time) error {
	return nil
}

func (c *MirrorConn) SetWriteDeadline(t time.Time) error {
	return nil
}

var (
	size  = 8192
	empty = make([]byte, size)
	types = [7]string{
		"Server Hello",
		"Change Cipher Spec",
		"Encrypted Extensions",
		"Certificate",
		"Certificate Verify",
		"Finished",
		"New Session Ticket",
	}
)

func Value(vals ...byte) (value int) {
	for i, val := range vals {
		value |= int(val) << ((len(vals) - i - 1) * 8)
	}
	return
}

// Server returns a new TLS server side connection
// using conn as the underlying transport.
// The configuration config must be non-nil and must include
// at least one certificate or else set GetCertificate.
func Server(ctx context.Context, conn net.Conn, config *Config) (*Conn, error) {
	remoteAddr := conn.RemoteAddr().String()
	if config.Show {
		fmt.Printf("REALITY remoteAddr: %v\n", remoteAddr)
	}

	target, err := config.DialContext(ctx, config.Type, config.Dest)
	if err != nil {
		conn.Close()
		return nil, errors.New("REALITY: failed to dial dest: " + err.Error())
	}

	if config.Xver == 1 || config.Xver == 2 {
		if _, err = proxyproto.HeaderProxyFromAddrs(config.Xver, conn.RemoteAddr(), conn.LocalAddr()).WriteTo(target); err != nil {
			target.Close()
			conn.Close()
			return nil, errors.New("REALITY: failed to send PROXY protocol: " + err.Error())
		}
	}

	underlying := conn
	if pc, ok := underlying.(*proxyproto.Conn); ok {
		underlying = pc.Raw() // for TCP splicing in io.Copy()
	}

	mutex := new(sync.Mutex)

	hs := serverHandshakeStateTLS13{
		c: &Conn{
			conn: &MirrorConn{
				Mutex:  mutex,
				Conn:   conn,
				Target: target,
			},
			config: config,
		},
		ctx: context.Background(),
	}

	copying := false

	waitGroup := new(sync.WaitGroup)
	waitGroup.Add(2)

	go func() {
		for {
			mutex.Lock()
			hs.clientHello, err = hs.c.readClientHello(context.Background()) // TODO: Change some rules in this function.
			if copying || err != nil || hs.c.vers != VersionTLS13 || !config.ServerNames[hs.clientHello.serverName] {
				break
			}
			for i, keyShare := range hs.clientHello.keyShares {
				if keyShare.group != X25519 || len(keyShare.data) != 32 {
					continue
				}
				if hs.c.AuthKey, err = curve25519.X25519(config.PrivateKey, keyShare.data); err != nil {
					break
				}
				if _, err = hkdf.New(sha256.New, hs.c.AuthKey, hs.clientHello.random[:20], []byte("REALITY")).Read(hs.c.AuthKey); err != nil {
					break
				}
				var aead cipher.AEAD
				if aesgcmPreferred(hs.clientHello.cipherSuites) {
					block, _ := aes.NewCipher(hs.c.AuthKey)
					aead, _ = cipher.NewGCM(block)
				} else {
					aead, _ = chacha20poly1305.New(hs.c.AuthKey)
				}
				if config.Show {
					fmt.Printf("REALITY remoteAddr: %v\ths.c.AuthKey[:16]: %v\tAEAD: %T\n", remoteAddr, hs.c.AuthKey[:16], aead)
				}
				ciphertext := make([]byte, 32)
				plainText := make([]byte, 32)
				copy(ciphertext, hs.clientHello.sessionId)
				copy(hs.clientHello.sessionId, plainText) // hs.clientHello.sessionId points to hs.clientHello.raw[39:]
				if _, err = aead.Open(plainText[:0], hs.clientHello.random[20:], ciphertext, hs.clientHello.raw); err != nil {
					break
				}
				copy(hs.clientHello.sessionId, ciphertext)
				copy(hs.c.ClientVer[:], plainText)
				hs.c.ClientTime = time.Unix(int64(binary.BigEndian.Uint32(plainText[4:])), 0)
				copy(hs.c.ClientShortId[:], plainText[8:])
				if config.Show {
					fmt.Printf("REALITY remoteAddr: %v\ths.c.ClientVer: %v\n", remoteAddr, hs.c.ClientVer)
					fmt.Printf("REALITY remoteAddr: %v\ths.c.ClientTime: %v\n", remoteAddr, hs.c.ClientTime)
					fmt.Printf("REALITY remoteAddr: %v\ths.c.ClientShortId: %v\n", remoteAddr, hs.c.ClientShortId)
				}
				if (config.MinClientVer == nil || Value(hs.c.ClientVer[:]...) >= Value(config.MinClientVer...)) &&
					(config.MaxClientVer == nil || Value(hs.c.ClientVer[:]...) <= Value(config.MaxClientVer...)) &&
					(config.MaxTimeDiff == 0 || time.Since(hs.c.ClientTime).Abs() <= config.MaxTimeDiff) &&
					(config.ShortIds[hs.c.ClientShortId]) {
					hs.c.conn = conn
				}
				hs.clientHello.keyShares[0].group = CurveID(i)
				break
			}
			if config.Show {
				fmt.Printf("REALITY remoteAddr: %v\ths.c.conn == conn: %v\n", remoteAddr, hs.c.conn == conn)
			}
			break
		}
		mutex.Unlock()
		if hs.c.conn != conn {
			io.Copy(target, underlying)
		}
		waitGroup.Done()
	}()

	go func() {
		s2cSaved := make([]byte, 0, size)
		buf := make([]byte, size)
		handshakeLen := 0
	f:
		for {
			runtime.Gosched()
			n, err := target.Read(buf)
			if n == 0 {
				if err != nil {
					conn.Close()
					waitGroup.Done()
					return
				}
				continue
			}
			mutex.Lock()
			s2cSaved = append(s2cSaved, buf[:n]...)
			if hs.c.conn != conn {
				copying = true // if the target already sent some data, just start bidirectional direct forwarding
				break
			}
			if len(s2cSaved) > size {
				break
			}
			for i, t := range types {
				if hs.c.out.handshakeLen[i] != 0 {
					continue
				}
				if i == 6 && len(s2cSaved) == 0 {
					break
				}
				if handshakeLen == 0 && len(s2cSaved) > recordHeaderLen {
					if Value(s2cSaved[1:3]...) != VersionTLS12 ||
						(i == 0 && (recordType(s2cSaved[0]) != recordTypeHandshake || s2cSaved[5] != typeServerHello)) ||
						(i == 1 && (recordType(s2cSaved[0]) != recordTypeChangeCipherSpec || s2cSaved[5] != 1)) ||
						(i > 1 && recordType(s2cSaved[0]) != recordTypeApplicationData) {
						break f
					}
					handshakeLen = recordHeaderLen + Value(s2cSaved[3:5]...)
				}
				if config.Show {
					fmt.Printf("REALITY remoteAddr: %v\tlen(s2cSaved): %v\t%v: %v\n", remoteAddr, len(s2cSaved), t, handshakeLen)
				}
				if handshakeLen > size { // too long
					break f
				}
				if i == 1 && handshakeLen > 0 && handshakeLen != 6 {
					break f
				}
				if i == 2 && handshakeLen > 512 {
					hs.c.out.handshakeLen[i] = handshakeLen
					hs.c.out.handshakeBuf = buf[:0]
					break
				}
				if i == 6 && handshakeLen > 0 {
					hs.c.out.handshakeLen[i] = handshakeLen
					break
				}
				if handshakeLen == 0 || len(s2cSaved) < handshakeLen {
					mutex.Unlock()
					continue f
				}
				if i == 0 {
					hs.hello = new(serverHelloMsg)
					if !hs.hello.unmarshal(s2cSaved[recordHeaderLen:handshakeLen]) ||
						hs.hello.vers != VersionTLS12 || hs.hello.supportedVersion != VersionTLS13 ||
						cipherSuiteTLS13ByID(hs.hello.cipherSuite) == nil ||
						hs.hello.serverShare.group != X25519 || len(hs.hello.serverShare.data) != 32 {
						break f
					}
				}
				hs.c.out.handshakeLen[i] = handshakeLen
				s2cSaved = s2cSaved[handshakeLen:]
				handshakeLen = 0
			}
			start := time.Now()
			err = hs.handshake()
			if config.Show {
				fmt.Printf("REALITY remoteAddr: %v\ths.handshake() err: %v\n", remoteAddr, err)
			}
			if err != nil {
				break
			}
			go func() { // TODO: Probe target's maxUselessRecords and some time-outs in advance.
				if handshakeLen-len(s2cSaved) > 0 {
					io.ReadFull(target, buf[:handshakeLen-len(s2cSaved)])
				}
				if n, err := target.Read(buf); !hs.c.handshakeComplete() {
					if err != nil {
						conn.Close()
					}
					if config.Show {
						fmt.Printf("REALITY remoteAddr: %v\ttime.Since(start): %v\tn: %v\terr: %v\n", remoteAddr, time.Since(start), n, err)
					}
				}
			}()
			err = hs.readClientFinished()
			if config.Show {
				fmt.Printf("REALITY remoteAddr: %v\ths.readClientFinished() err: %v\n", remoteAddr, err)
			}
			if err != nil {
				break
			}
			atomic.StoreUint32(&hs.c.handshakeStatus, 1)
			break
		}
		mutex.Unlock()
		if hs.c.out.handshakeLen[0] == 0 { // if the target sent an incorrect Server Hello, or before that
			if hs.c.conn == conn { // if we processed the Client Hello successfully but the target did not
				waitGroup.Add(1)
				go func() {
					io.Copy(target, underlying)
					waitGroup.Done()
				}()
			}
			conn.Write(s2cSaved)
			io.Copy(underlying, target)
		}
		waitGroup.Done()
	}()

	waitGroup.Wait()
	target.Close()
	if config.Show {
		fmt.Printf("REALITY remoteAddr: %v\ths.c.handshakeStatus: %v\n", remoteAddr, atomic.LoadUint32(&hs.c.handshakeStatus))
	}
	if atomic.LoadUint32(&hs.c.handshakeStatus) == 1 {
		return hs.c, nil
	}
	conn.Close()
	return nil, errors.New("REALITY: processed invalid connection") // TODO: Add details.

	/*
		c := &Conn{
			conn:   conn,
			config: config,
		}
		c.handshakeFn = c.serverHandshake
		return c
	*/
}

// Client returns a new TLS client side connection
// using conn as the underlying transport.
// The config cannot be nil: users must set either ServerName or
// InsecureSkipVerify in the config.
func Client(conn net.Conn, config *Config) *Conn {
	c := &Conn{
		conn:     conn,
		config:   config,
		isClient: true,
	}
	c.handshakeFn = c.clientHandshake
	return c
}

// A listener implements a network listener (net.Listener) for TLS connections.
type listener struct {
	net.Listener
	config *Config
	conns  chan net.Conn
	err    error
}

// Accept waits for and returns the next incoming TLS connection.
// The returned connection is of type *Conn.
func (l *listener) Accept() (net.Conn, error) {
	/*
		c, err := l.Listener.Accept()
		if err != nil {
			return nil, err
		}
		return Server(c, l.config), nil
	*/
	if c, ok := <-l.conns; ok {
		return c, nil
	}
	return nil, l.err
}

// NewListener creates a Listener which accepts connections from an inner
// Listener and wraps each connection with Server.
// The configuration config must be non-nil and must include
// at least one certificate or else set GetCertificate.
func NewListener(inner net.Listener, config *Config) net.Listener {
	l := new(listener)
	l.Listener = inner
	l.config = config
	{
		l.conns = make(chan net.Conn)
		go func() {
			for {
				c, err := l.Listener.Accept()
				if err != nil {
					l.err = err
					close(l.conns)
					return
				}
				go func() {
					defer recover()
					c, err = Server(context.Background(), c, l.config)
					if err == nil {
						l.conns <- c
					}
				}()
			}
		}()
	}
	return l
}

// Listen creates a TLS listener accepting connections on the
// given network address using net.Listen.
// The configuration config must be non-nil and must include
// at least one certificate or else set GetCertificate.
func Listen(network, laddr string, config *Config) (net.Listener, error) {
	if config == nil || len(config.Certificates) == 0 &&
		config.GetCertificate == nil && config.GetConfigForClient == nil {
		return nil, errors.New("tls: neither Certificates, GetCertificate, nor GetConfigForClient set in Config")
	}
	l, err := net.Listen(network, laddr)
	if err != nil {
		return nil, err
	}
	return NewListener(l, config), nil
}

type timeoutError struct{}

func (timeoutError) Error() string   { return "tls: DialWithDialer timed out" }
func (timeoutError) Timeout() bool   { return true }
func (timeoutError) Temporary() bool { return true }

// DialWithDialer connects to the given network address using dialer.Dial and
// then initiates a TLS handshake, returning the resulting TLS connection. Any
// timeout or deadline given in the dialer apply to connection and TLS
// handshake as a whole.
//
// DialWithDialer interprets a nil configuration as equivalent to the zero
// configuration; see the documentation of Config for the defaults.
//
// DialWithDialer uses context.Background internally; to specify the context,
// use Dialer.DialContext with NetDialer set to the desired dialer.
func DialWithDialer(dialer *net.Dialer, network, addr string, config *Config) (*Conn, error) {
	return dial(context.Background(), dialer, network, addr, config)
}

func dial(ctx context.Context, netDialer *net.Dialer, network, addr string, config *Config) (*Conn, error) {
	if netDialer.Timeout != 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, netDialer.Timeout)
		defer cancel()
	}

	if !netDialer.Deadline.IsZero() {
		var cancel context.CancelFunc
		ctx, cancel = context.WithDeadline(ctx, netDialer.Deadline)
		defer cancel()
	}

	rawConn, err := netDialer.DialContext(ctx, network, addr)
	if err != nil {
		return nil, err
	}

	colonPos := strings.LastIndex(addr, ":")
	if colonPos == -1 {
		colonPos = len(addr)
	}
	hostname := addr[:colonPos]

	if config == nil {
		config = defaultConfig()
	}
	// If no ServerName is set, infer the ServerName
	// from the hostname we're connecting to.
	if config.ServerName == "" {
		// Make a copy to avoid polluting argument or default.
		c := config.Clone()
		c.ServerName = hostname
		config = c
	}

	conn := Client(rawConn, config)
	if err := conn.HandshakeContext(ctx); err != nil {
		rawConn.Close()
		return nil, err
	}
	return conn, nil
}

// Dial connects to the given network address using net.Dial
// and then initiates a TLS handshake, returning the resulting
// TLS connection.
// Dial interprets a nil configuration as equivalent to
// the zero configuration; see the documentation of Config
// for the defaults.
func Dial(network, addr string, config *Config) (*Conn, error) {
	return DialWithDialer(new(net.Dialer), network, addr, config)
}

// Dialer dials TLS connections given a configuration and a Dialer for the
// underlying connection.
type Dialer struct {
	// NetDialer is the optional dialer to use for the TLS connections'
	// underlying TCP connections.
	// A nil NetDialer is equivalent to the net.Dialer zero value.
	NetDialer *net.Dialer

	// Config is the TLS configuration to use for new connections.
	// A nil configuration is equivalent to the zero
	// configuration; see the documentation of Config for the
	// defaults.
	Config *Config
}

// Dial connects to the given network address and initiates a TLS
// handshake, returning the resulting TLS connection.
//
// The returned Conn, if any, will always be of type *Conn.
//
// Dial uses context.Background internally; to specify the context,
// use DialContext.
func (d *Dialer) Dial(network, addr string) (net.Conn, error) {
	return d.DialContext(context.Background(), network, addr)
}

func (d *Dialer) netDialer() *net.Dialer {
	if d.NetDialer != nil {
		return d.NetDialer
	}
	return new(net.Dialer)
}

// DialContext connects to the given network address and initiates a TLS
// handshake, returning the resulting TLS connection.
//
// The provided Context must be non-nil. If the context expires before
// the connection is complete, an error is returned. Once successfully
// connected, any expiration of the context will not affect the
// connection.
//
// The returned Conn, if any, will always be of type *Conn.
func (d *Dialer) DialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	c, err := dial(ctx, d.netDialer(), network, addr, d.Config)
	if err != nil {
		// Don't return c (a typed nil) in an interface.
		return nil, err
	}
	return c, nil
}

// LoadX509KeyPair reads and parses a public/private key pair from a pair
// of files. The files must contain PEM encoded data. The certificate file
// may contain intermediate certificates following the leaf certificate to
// form a certificate chain. On successful return, Certificate.Leaf will
// be nil because the parsed form of the certificate is not retained.
func LoadX509KeyPair(certFile, keyFile string) (Certificate, error) {
	certPEMBlock, err := os.ReadFile(certFile)
	if err != nil {
		return Certificate{}, err
	}
	keyPEMBlock, err := os.ReadFile(keyFile)
	if err != nil {
		return Certificate{}, err
	}
	return X509KeyPair(certPEMBlock, keyPEMBlock)
}

// X509KeyPair parses a public/private key pair from a pair of
// PEM encoded data. On successful return, Certificate.Leaf will be nil because
// the parsed form of the certificate is not retained.
func X509KeyPair(certPEMBlock, keyPEMBlock []byte) (Certificate, error) {
	fail := func(err error) (Certificate, error) { return Certificate{}, err }

	var cert Certificate
	var skippedBlockTypes []string
	for {
		var certDERBlock *pem.Block
		certDERBlock, certPEMBlock = pem.Decode(certPEMBlock)
		if certDERBlock == nil {
			break
		}
		if certDERBlock.Type == "CERTIFICATE" {
			cert.Certificate = append(cert.Certificate, certDERBlock.Bytes)
		} else {
			skippedBlockTypes = append(skippedBlockTypes, certDERBlock.Type)
		}
	}

	if len(cert.Certificate) == 0 {
		if len(skippedBlockTypes) == 0 {
			return fail(errors.New("tls: failed to find any PEM data in certificate input"))
		}
		if len(skippedBlockTypes) == 1 && strings.HasSuffix(skippedBlockTypes[0], "PRIVATE KEY") {
			return fail(errors.New("tls: failed to find certificate PEM data in certificate input, but did find a private key; PEM inputs may have been switched"))
		}
		return fail(fmt.Errorf("tls: failed to find \"CERTIFICATE\" PEM block in certificate input after skipping PEM blocks of the following types: %v", skippedBlockTypes))
	}

	skippedBlockTypes = skippedBlockTypes[:0]
	var keyDERBlock *pem.Block
	for {
		keyDERBlock, keyPEMBlock = pem.Decode(keyPEMBlock)
		if keyDERBlock == nil {
			if len(skippedBlockTypes) == 0 {
				return fail(errors.New("tls: failed to find any PEM data in key input"))
			}
			if len(skippedBlockTypes) == 1 && skippedBlockTypes[0] == "CERTIFICATE" {
				return fail(errors.New("tls: found a certificate rather than a key in the PEM for the private key"))
			}
			return fail(fmt.Errorf("tls: failed to find PEM block with type ending in \"PRIVATE KEY\" in key input after skipping PEM blocks of the following types: %v", skippedBlockTypes))
		}
		if keyDERBlock.Type == "PRIVATE KEY" || strings.HasSuffix(keyDERBlock.Type, " PRIVATE KEY") {
			break
		}
		skippedBlockTypes = append(skippedBlockTypes, keyDERBlock.Type)
	}

	// We don't need to parse the public key for TLS, but we so do anyway
	// to check that it looks sane and matches the private key.
	x509Cert, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		return fail(err)
	}

	cert.PrivateKey, err = parsePrivateKey(keyDERBlock.Bytes)
	if err != nil {
		return fail(err)
	}

	switch pub := x509Cert.PublicKey.(type) {
	case *rsa.PublicKey:
		priv, ok := cert.PrivateKey.(*rsa.PrivateKey)
		if !ok {
			return fail(errors.New("tls: private key type does not match public key type"))
		}
		if pub.N.Cmp(priv.N) != 0 {
			return fail(errors.New("tls: private key does not match public key"))
		}
	case *ecdsa.PublicKey:
		priv, ok := cert.PrivateKey.(*ecdsa.PrivateKey)
		if !ok {
			return fail(errors.New("tls: private key type does not match public key type"))
		}
		if pub.X.Cmp(priv.X) != 0 || pub.Y.Cmp(priv.Y) != 0 {
			return fail(errors.New("tls: private key does not match public key"))
		}
	case ed25519.PublicKey:
		priv, ok := cert.PrivateKey.(ed25519.PrivateKey)
		if !ok {
			return fail(errors.New("tls: private key type does not match public key type"))
		}
		if !bytes.Equal(priv.Public().(ed25519.PublicKey), pub) {
			return fail(errors.New("tls: private key does not match public key"))
		}
	default:
		return fail(errors.New("tls: unknown public key algorithm"))
	}

	return cert, nil
}

// Attempt to parse the given private key DER block. OpenSSL 0.9.8 generates
// PKCS #1 private keys by default, while OpenSSL 1.0.0 generates PKCS #8 keys.
// OpenSSL ecparam generates SEC1 EC private keys for ECDSA. We try all three.
func parsePrivateKey(der []byte) (crypto.PrivateKey, error) {
	if key, err := x509.ParsePKCS1PrivateKey(der); err == nil {
		return key, nil
	}
	if key, err := x509.ParsePKCS8PrivateKey(der); err == nil {
		switch key := key.(type) {
		case *rsa.PrivateKey, *ecdsa.PrivateKey, ed25519.PrivateKey:
			return key, nil
		default:
			return nil, errors.New("tls: found unknown private key type in PKCS#8 wrapping")
		}
	}
	if key, err := x509.ParseECPrivateKey(der); err == nil {
		return key, nil
	}

	return nil, errors.New("tls: failed to parse private key")
}
