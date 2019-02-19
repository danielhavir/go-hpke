package hpke

import (
	"bytes"
	"crypto/rand"
	"testing"
)

func testHPKE(t *testing.T, params *Params) {
	random := rand.Reader
	prv, pub, err := GenerateKeypair(params, random)
	if err != nil {
		t.Error(err)
	}

	msg := make([]byte, 64)
	rand.Read(msg)

	ct, ephemeral, err := Encrypt(params, random, pub, msg, nil, nil)
	if err != nil {
		t.Error(err)
	}

	pt, err := Decrypt(params, prv, ephemeral, ct, nil, nil)
	if err != nil {
		t.Error(err)
	}

	if !bytes.Equal(msg, pt) {
		t.Error("plaintext do not match")
	}
}

func TestX25519_SHA256_AES_GCM_128(t *testing.T) {
	params := X25519_SHA256_AES_GCM_128
	testHPKE(t, params)
}

func TestX25519_SHA256_ChaCha20Poly1305(t *testing.T) {
	params := X25519_SHA256_ChaCha20Poly1305
	testHPKE(t, params)
}

func TestP256_SHA256_AES_GCM_128(t *testing.T) {
	params := P256_SHA256_AES_GCM_128
	testHPKE(t, params)
}

func TestP256_SHA256_ChaCha20Poly1305(t *testing.T) {
	params := P256_SHA256_ChaCha20Poly1305
	testHPKE(t, params)
}

func TestP521_SHA512_AES_GCM_256(t *testing.T) {
	params := P521_SHA512_AES_GCM_256
	testHPKE(t, params)
}

func TestP521_SHA512_ChaCha20Poly1305(t *testing.T) {
	params := P521_SHA512_ChaCha20Poly1305
	testHPKE(t, params)
}
