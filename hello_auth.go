package reality

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/mlkem"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"time"

	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/hkdf"
)

// ClientHelloAuth contains the authenticated REALITY fields of a ClientHello.
type ClientHelloAuth struct {
	// AuthKey is a connection secret, not a TLS traffic key. Do not log it.
	AuthKey       [32]byte
	ClientVer     [3]byte
	ClientTime    time.Time
	ClientShortId [8]byte
}

// VerifyClientHello checks REALITY authentication and config's admission policy.
// raw is one handshake message with its 4-byte header, without TLS record headers.
// It is neither modified nor retained. The caller must preserve original records
// and read-ahead bytes for subsequent server processing.
// GetConfigForClient, GetEncryptedClientHelloKeys and ECH keys must be unset.
// Success does not complete TLS, authenticate an application user, or prevent replay.
func VerifyClientHello(raw []byte, config *Config) (*ClientHelloAuth, error) {
	if config == nil {
		return nil, errors.New("REALITY: missing config")
	}
	if config.GetConfigForClient != nil || config.GetEncryptedClientHelloKeys != nil || len(config.EncryptedClientHelloKeys) != 0 {
		return nil, errors.New("REALITY: standalone verification requires a static config without ECH keys")
	}
	if len(raw) < 4 || raw[0] != typeClientHello || len(raw)-4 > maxHandshake || Value(raw[1:4]...) != len(raw)-4 {
		return nil, errors.New("REALITY: invalid ClientHello framing")
	}
	hello := new(clientHelloMsg)
	if !hello.unmarshal(raw) {
		return nil, errors.New("REALITY: invalid ClientHello")
	}
	if len(hello.encryptedClientHello) != 0 {
		if _, _, _, _, _, err := parseECHExt(hello.encryptedClientHello); err != nil {
			return nil, err
		}
	}
	version, _ := config.mutualVersion(roleServer, false, hello.supportedVersions)
	return verifyClientHello(hello, version, config, nil)
}

func verifyClientHello(hello *clientHelloMsg, version uint16, config *Config, authKey *[32]byte) (*ClientHelloAuth, error) {
	if version != VersionTLS13 || !config.ServerNames[hello.serverName] {
		return nil, errors.New("REALITY: unsupported TLS version or server name")
	}
	var peerPub, peerPub2 []byte
	// Require X25519MLKEM768 before optional X25519.
	for _, keyShare := range hello.keyShares {
		if keyShare.group == X25519MLKEM768 && len(keyShare.data) == mlkem.EncapsulationKeySize768+32 {
			if peerPub2 != nil {
				peerPub2 = nil
				break
			}
			peerPub2 = keyShare.data[mlkem.EncapsulationKeySize768:]
			continue
		}
		if keyShare.group == X25519 && len(keyShare.data) == 32 {
			if peerPub != nil {
				peerPub2 = nil
				break
			}
			peerPub = keyShare.data
			break
		}
	}
	if peerPub2 == nil {
		return nil, errors.New("REALITY: missing or out-of-order X25519MLKEM768 key share")
	}
	if peerPub == nil {
		peerPub = peerPub2
	}
	privateKey := config.PrivateKey
	if authKey != nil {
		// Use a throwaway scalar to retain low-order rejection with a supplied key.
		privateKey = make([]byte, 32)
	}
	key, err := curve25519.X25519(privateKey, peerPub)
	if err != nil {
		return nil, err
	}
	if authKey == nil {
		if _, err := hkdf.New(sha256.New, key, hello.random[:20], []byte("REALITY")).Read(key); err != nil {
			return nil, err
		}
	} else {
		key = authKey[:]
	}
	block, _ := aes.NewCipher(key)
	aead, _ := cipher.NewGCM(block)
	// Match the original 32-byte copy; any SessionID tail stays in AAD.
	var ciphertext [32]byte
	copy(ciphertext[:], hello.sessionId)
	aad := bytes.Clone(hello.original)
	const sessionIDOffset = 4 + 2 + 32 + 1
	clear(aad[sessionIDOffset : sessionIDOffset+min(len(hello.sessionId), len(ciphertext))])
	plainText, err := aead.Open(nil, hello.random[20:], ciphertext[:], aad)
	if err != nil {
		return nil, err
	}
	auth := &ClientHelloAuth{ClientTime: time.Unix(int64(binary.BigEndian.Uint32(plainText[4:])), 0)}
	copy(auth.AuthKey[:], key)
	copy(auth.ClientVer[:], plainText)
	copy(auth.ClientShortId[:], plainText[8:])
	if (config.MinClientVer != nil && Value(auth.ClientVer[:]...) < Value(config.MinClientVer...)) ||
		(config.MaxClientVer != nil && Value(auth.ClientVer[:]...) > Value(config.MaxClientVer...)) ||
		(config.MaxTimeDiff != 0 && time.Since(auth.ClientTime).Abs() > config.MaxTimeDiff) ||
		!config.ShortIds[auth.ClientShortId] {
		return nil, errors.New("REALITY: client version, timestamp or shortId not allowed")
	}
	return auth, nil
}
