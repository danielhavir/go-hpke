package hpke

import (
	"bytes"
	"crypto/rand"
	"testing"
)

func testBaseHPKE(t *testing.T, params *Params) {
	random := rand.Reader
	prv, pub, err := GenerateKeyPair(params, random)
	if err != nil {
		t.Error(err)
	}

	counter := 0

	msg := make([]byte, 64)
	rand.Read(msg)
	aad := make([]byte, 16)
	rand.Read(aad)

	ct, ephemeral, err := EncryptBase(params, random, pub, msg, aad, nil, counter)
	if err != nil {
		t.Error(err)
	}

	pt, err := DecryptBase(params, prv, ephemeral, ct, aad, nil, counter)
	if err != nil {
		t.Error(err)
	}

	if !bytes.Equal(msg, pt) {
		t.Error("plaintext do not match")
	}

	counter++
	_, err = DecryptBase(params, prv, ephemeral, ct, aad, nil, counter)
	if err == nil {
		t.Error("different counter value should invalidate decryption")
	}

	info := make([]byte, 32)
	rand.Read(info)

	ct, ephemeral, err = EncryptBase(params, random, pub, msg, aad, info, counter)
	if err != nil {
		t.Error(err)
	}

	pt, err = DecryptBase(params, prv, ephemeral, ct, aad, info, counter)
	if err != nil {
		t.Error(err)
	}

	if !bytes.Equal(msg, pt) {
		t.Error("plaintext do not match when info is included")
	}
}

func TestBASE_X25519_SHA256_AES_GCM_128(t *testing.T) {
	params, err := GetParams(BASE_X25519_SHA256_AES_GCM_128)
	if err != nil {
		t.Error(err)
	}
	testBaseHPKE(t, params)
}

func TestBASE_X25519_SHA256_ChaCha20Poly1305(t *testing.T) {
	params, err := GetParams(BASE_X25519_SHA256_ChaCha20Poly1305)
	if err != nil {
		t.Error(err)
	}
	testBaseHPKE(t, params)
}

func TestBASE_P256_SHA256_AES_GCM_128(t *testing.T) {
	params, err := GetParams(BASE_P256_SHA256_AES_GCM_128)
	if err != nil {
		t.Error(err)
	}
	testBaseHPKE(t, params)
}

func TestBASE_P256_SHA256_ChaCha20Poly1305(t *testing.T) {
	params, err := GetParams(BASE_P256_SHA256_ChaCha20Poly1305)
	if err != nil {
		t.Error(err)
	}
	testBaseHPKE(t, params)
}

func TestBASE_P521_SHA512_AES_GCM_256(t *testing.T) {
	params, err := GetParams(BASE_P521_SHA512_AES_GCM_256)
	if err != nil {
		t.Error(err)
	}
	testBaseHPKE(t, params)
}

func TestBASE_P521_SHA512_ChaCha20Poly1305(t *testing.T) {
	params, err := GetParams(BASE_P521_SHA512_ChaCha20Poly1305)
	if err != nil {
		t.Error(err)
	}
	testBaseHPKE(t, params)
}

func testPSKHPKE(t *testing.T, params *Params) {
	random := rand.Reader
	prv, pub, err := GenerateKeyPair(params, random)
	if err != nil {
		t.Error(err)
	}

	counter := 1

	msg := make([]byte, 64)
	rand.Read(msg)
	aad := make([]byte, 16)
	rand.Read(aad)
	psk := make([]byte, 32)
	rand.Read(psk)
	pskId := make([]byte, 16)
	rand.Read(pskId)

	ct, ephemeral, err := EncryptPSK(params, random, pub, msg, aad, psk, pskId, nil, counter)
	if err != nil {
		t.Error(err)
	}

	pt, err := DecryptPSK(params, prv, ephemeral, ct, aad, psk, pskId, nil, counter)
	if err != nil {
		t.Error(err)
	}

	if !bytes.Equal(msg, pt) {
		t.Error("plaintext do not match")
	}

	counter++
	_, err = DecryptPSK(params, prv, ephemeral, ct, aad, psk, pskId, nil, counter)
	if err == nil {
		t.Error("different counter value should invalidate decryption")
	}

	malPsk := make([]byte, 32)
	rand.Read(malPsk)
	malPskId := make([]byte, 16)
	rand.Read(malPskId)
	_, err = DecryptPSK(params, prv, ephemeral, ct, aad, malPsk, malPskId, nil, counter)
	if err == nil {
		t.Error("different pre-shared key does not invalidate decryption")
	}

	info := make([]byte, 32)
	rand.Read(info)

	ct, ephemeral, err = EncryptPSK(params, random, pub, msg, aad, psk, pskId, info, counter)
	if err != nil {
		t.Error(err)
	}

	pt, err = DecryptPSK(params, prv, ephemeral, ct, aad, psk, pskId, info, counter)
	if err != nil {
		t.Error(err)
	}

	if !bytes.Equal(msg, pt) {
		t.Error("plaintext do not match when info is included")
	}
}

func TestPSK_X25519_SHA256_AES_GCM_128(t *testing.T) {
	params, err := GetParams(PSK_X25519_SHA256_AES_GCM_128)
	if err != nil {
		t.Error(err)
	}
	testPSKHPKE(t, params)
}

func TestPSK_X25519_SHA256_ChaCha20Poly1305(t *testing.T) {
	params, err := GetParams(PSK_X25519_SHA256_ChaCha20Poly1305)
	if err != nil {
		t.Error(err)
	}
	testPSKHPKE(t, params)
}

func TestPSK_P256_SHA256_AES_GCM_128(t *testing.T) {
	params, err := GetParams(PSK_P256_SHA256_AES_GCM_128)
	if err != nil {
		t.Error(err)
	}
	testPSKHPKE(t, params)
}

func TestPSK_P256_SHA256_ChaCha20Poly1305(t *testing.T) {
	params, err := GetParams(PSK_P256_SHA256_ChaCha20Poly1305)
	if err != nil {
		t.Error(err)
	}
	testPSKHPKE(t, params)
}

func TestPSK_P521_SHA512_AES_GCM_256(t *testing.T) {
	params, err := GetParams(PSK_P521_SHA512_AES_GCM_256)
	if err != nil {
		t.Error(err)
	}
	testPSKHPKE(t, params)
}

func TestPSK_P521_SHA512_ChaCha20Poly1305(t *testing.T) {
	params, err := GetParams(PSK_P521_SHA512_ChaCha20Poly1305)
	if err != nil {
		t.Error(err)
	}
	testPSKHPKE(t, params)
}

func testAuthHPKE(t *testing.T, params *Params) {
	random := rand.Reader
	skI, pkI, err := GenerateKeyPair(params, random)
	if err != nil {
		t.Error(err)
	}
	skR, pkR, err := GenerateKeyPair(params, random)
	if err != nil {
		t.Error(err)
	}

	counter := 2

	msg := make([]byte, 64)
	rand.Read(msg)
	aad := make([]byte, 16)
	rand.Read(aad)

	ct, ephemeral, err := EncryptAuth(params, random, pkR, skI, msg, aad, nil, counter)
	if err != nil {
		t.Error(err)
	}

	pt, err := DecryptAuth(params, skR, pkI, ephemeral, ct, aad, nil, counter)
	if err != nil {
		t.Error(err)
	}

	if !bytes.Equal(msg, pt) {
		t.Error("plaintext do not match")
	}

	counter++
	_, err = DecryptAuth(params, skR, pkI, ephemeral, ct, aad, nil, counter)
	if err == nil {
		t.Error("different counter value should invalidate decryption")
	}

	_, pub, err := GenerateKeyPair(params, random)
	if err != nil {
		t.Error(err)
	}
	_, err = DecryptAuth(params, skR, pub, ephemeral, ct, aad, nil, counter)
	if err == nil {
		t.Error("different initiator public key does not invalidate decryption")
	}

	info := make([]byte, 32)
	rand.Read(info)

	ct, ephemeral, err = EncryptAuth(params, random, pkR, skI, msg, aad, info, counter)
	if err != nil {
		t.Error(err)
	}

	pt, err = DecryptAuth(params, skR, pkI, ephemeral, ct, aad, info, counter)
	if err != nil {
		t.Error(err)
	}

	if !bytes.Equal(msg, pt) {
		t.Error("plaintext do not match when info is included")
	}
}

func TestAUTH_X25519_SHA256_AES_GCM_128(t *testing.T) {
	params, err := GetParams(AUTH_X25519_SHA256_AES_GCM_128)
	if err != nil {
		t.Error(err)
	}
	testAuthHPKE(t, params)
}

func TestAUTH_X25519_SHA256_ChaCha20Poly1305(t *testing.T) {
	params, err := GetParams(AUTH_X25519_SHA256_ChaCha20Poly1305)
	if err != nil {
		t.Error(err)
	}
	testAuthHPKE(t, params)
}

func TestAUTH_P256_SHA256_AES_GCM_128(t *testing.T) {
	params, err := GetParams(AUTH_P256_SHA256_AES_GCM_128)
	if err != nil {
		t.Error(err)
	}
	testAuthHPKE(t, params)
}

func TestAUTH_P256_SHA256_ChaCha20Poly1305(t *testing.T) {
	params, err := GetParams(AUTH_P256_SHA256_ChaCha20Poly1305)
	if err != nil {
		t.Error(err)
	}
	testAuthHPKE(t, params)
}

func TestAUTH_P521_SHA512_AES_GCM_256(t *testing.T) {
	params, err := GetParams(AUTH_P521_SHA512_AES_GCM_256)
	if err != nil {
		t.Error(err)
	}
	testAuthHPKE(t, params)
}

func TestAUTH_P521_SHA512_ChaCha20Poly1305(t *testing.T) {
	params, err := GetParams(AUTH_P521_SHA512_ChaCha20Poly1305)
	if err != nil {
		t.Error(err)
	}
	testAuthHPKE(t, params)
}
