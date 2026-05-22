package reality

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"time"

	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/hkdf"
)

func (c *Config) applyRealityClientHello(hello *clientHelloMsg, keys *keySharePrivateKeys) error {
	if len(c.PublicKey) == 0 && len(c.ShortId) == 0 {
		return nil
	}
	if len(c.PublicKey) != 32 {
		return errors.New("REALITY: publicKey == nil")
	}
	if keys == nil || keys.ecdhe == nil {
		return errors.New("REALITY: TLS 1.3 X25519 key share is unavailable")
	}
	publicKey, err := ecdh.X25519().NewPublicKey(c.PublicKey)
	if err != nil {
		return errors.New("REALITY: publicKey == nil")
	}
	authKey, err := keys.ecdhe.ECDH(publicKey)
	if err != nil || authKey == nil {
		return errors.New("REALITY: sharedKey == nil")
	}
	if _, err = hkdf.New(sha256.New, authKey, hello.random[:20], []byte("REALITY")).Read(authKey); err != nil {
		return err
	}

	plainText := make([]byte, 32)
	hello.sessionId = make([]byte, 32)
	associatedData, err := hello.marshal()
	if err != nil {
		return err
	}

	plainText[0] = 26
	plainText[1] = 4
	plainText[2] = 17
	binary.BigEndian.PutUint32(plainText[4:], uint32(time.Now().Unix()))
	copy(plainText[8:], c.ShortId)

	block, _ := aes.NewCipher(authKey)
	aead, _ := cipher.NewGCM(block)
	hello.sessionId = aead.Seal(plainText[:0], hello.random[20:], plainText[:16], associatedData)
	return nil
}

func (c *Conn) acceptRealityClientHello(hello *clientHelloMsg) error {
	if c.config == nil || len(c.config.PrivateKey) == 0 || len(c.config.ShortIds) == 0 {
		return nil
	}
	if c.vers != VersionTLS13 {
		return errors.New("REALITY: unsupported TLS version")
	}
	if !c.config.ServerNames[hello.serverName] {
		return errors.New("REALITY: server name mismatch")
	}
	if len(hello.sessionId) != 32 {
		return errors.New("REALITY: missing client session id")
	}

	var peerPub []byte
	for _, keyShare := range hello.keyShares {
		if keyShare.group == X25519 && len(keyShare.data) == 32 {
			peerPub = keyShare.data
			break
		}
		if keyShare.group == X25519MLKEM768 && len(keyShare.data) >= 32 {
			peerPub = keyShare.data[len(keyShare.data)-32:]
		}
	}
	if peerPub == nil {
		return errors.New("REALITY: missing X25519 key share")
	}

	authKey, err := curve25519.X25519(c.config.PrivateKey, peerPub)
	if err != nil || authKey == nil {
		return errors.New("REALITY: sharedKey == nil")
	}
	if _, err = hkdf.New(sha256.New, authKey, hello.random[:20], []byte("REALITY")).Read(authKey); err != nil {
		return err
	}

	cipherText := make([]byte, 32)
	plainText := make([]byte, 32)
	copy(cipherText, hello.sessionId)
	copy(hello.sessionId, plainText)
	block, _ := aes.NewCipher(authKey)
	aead, _ := cipher.NewGCM(block)
	if _, err = aead.Open(plainText[:0], hello.random[20:], cipherText, hello.original); err != nil {
		copy(hello.sessionId, cipherText)
		return err
	}
	copy(hello.sessionId, cipherText)

	copy(c.ClientVer[:], plainText)
	c.ClientTime = time.Unix(int64(binary.BigEndian.Uint32(plainText[4:])), 0)
	copy(c.ClientShortId[:], plainText[8:])
	if (c.config.MinClientVer != nil && Value(c.ClientVer[:]...) < Value(c.config.MinClientVer...)) ||
		(c.config.MaxClientVer != nil && Value(c.ClientVer[:]...) > Value(c.config.MaxClientVer...)) ||
		(c.config.MaxTimeDiff != 0 && time.Since(c.ClientTime).Abs() > c.config.MaxTimeDiff) ||
		!c.config.ShortIds[c.ClientShortId] {
		return errors.New("REALITY: authentication failed")
	}
	c.AuthKey = authKey
	return nil
}
