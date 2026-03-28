package hem

// SoftwareCipherEncrypt and SoftwareCipherDecrypt are the software equivalents of
// CipherEncrypt / CipherDecrypt running on HEM in ECDH mode.
//
// HEM flow (cipher/encrypt with ext_kid or pubkey):
//   1. raw = X25519(kid_priv, peer_pub)
//   2. aesKey = HKDF-SHA256(IKM=raw, salt=nil, info="encedo-aes", L=32)
//   3. ciphertext = AES-256-GCM(aesKey, iv=16B random, plaintext, aad)
//
// privKey: raw 32B Curve25519 private key — software stand-in for KID stored on HEM.
// peerPub: raw 32B Curve25519 public key — equivalent to ext_kid's pubkey or provided pubkey.

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"io"

	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/hkdf"
)

const hemHKDFInfo = "encedo-aes"
const hemGCMNonceSize = 16

// SoftwareCipherEncrypt encrypts plaintext using ECDH(privKey, peerPub) + HKDF + AES-256-GCM.
// Returns iv (16B), ciphertext, and tag (16B) — same layout as HEM CipherEncrypt response.
// aad may be nil (no additional authenticated data) or exactly 16 bytes.
func SoftwareCipherEncrypt(privKey, peerPub, plaintext, aad []byte) (iv, ct, tag []byte, err error) {
	aesKey, err := hemDeriveKey(privKey, peerPub)
	if err != nil {
		return nil, nil, nil, err
	}
	defer zeroBytes(aesKey)

	block, err := aes.NewCipher(aesKey)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("aes: %w", err)
	}
	gcm, err := cipher.NewGCMWithNonceSize(block, hemGCMNonceSize)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("gcm: %w", err)
	}

	iv = make([]byte, hemGCMNonceSize)
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return nil, nil, nil, fmt.Errorf("rand iv: %w", err)
	}

	sealed := gcm.Seal(nil, iv, plaintext, aad)
	tagOff := len(sealed) - gcm.Overhead()
	return iv, sealed[:tagOff], sealed[tagOff:], nil
}

// SoftwareCipherDecrypt decrypts ciphertext using ECDH(privKey, peerPub) + HKDF + AES-256-GCM.
// iv must be 16B, tag must be 16B — same as returned by SoftwareCipherEncrypt / HEM CipherEncrypt.
func SoftwareCipherDecrypt(privKey, peerPub, iv, ct, tag, aad []byte) ([]byte, error) {
	aesKey, err := hemDeriveKey(privKey, peerPub)
	if err != nil {
		return nil, err
	}
	defer zeroBytes(aesKey)

	block, err := aes.NewCipher(aesKey)
	if err != nil {
		return nil, fmt.Errorf("aes: %w", err)
	}
	gcm, err := cipher.NewGCMWithNonceSize(block, hemGCMNonceSize)
	if err != nil {
		return nil, fmt.Errorf("gcm: %w", err)
	}

	combined := make([]byte, len(ct)+len(tag))
	copy(combined, ct)
	copy(combined[len(ct):], tag)
	return gcm.Open(nil, iv, combined, aad)
}

// hemDeriveKey performs X25519(privKey, peerPub) then HKDF-SHA256(info="encedo-aes") → 32B AES key.
func hemDeriveKey(privKey, peerPub []byte) ([]byte, error) {
	raw, err := curve25519.X25519(privKey, peerPub)
	if err != nil {
		return nil, fmt.Errorf("X25519: %w", err)
	}
	defer zeroBytes(raw)

	key := make([]byte, 32)
	r := hkdf.New(sha256.New, raw, nil, []byte(hemHKDFInfo))
	if _, err := io.ReadFull(r, key); err != nil {
		return nil, fmt.Errorf("hkdf: %w", err)
	}
	return key, nil
}
