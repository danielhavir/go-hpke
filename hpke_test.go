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

	msg := make([]byte, 64)
	rand.Read(msg)
	aad := make([]byte, 16)
	rand.Read(aad)

	ct, ephemeral, err := EncryptBase(params, random, pub, msg, aad)
	if err != nil {
		t.Error(err)
	}

	pt, err := DecryptBase(params, prv, ephemeral, ct, aad)
	if err != nil {
		t.Error(err)
	}

	if !bytes.Equal(msg, pt) {
		t.Error("plaintext do not match")
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

func TestBASE_P256_SHA256_XChaCha20Blake2bSIV(t *testing.T) {
	params, err := GetParams(BASE_P256_SHA256_XChaCha20Blake2bSIV)
	if err != nil {
		t.Error(err)
	}
	testBaseHPKE(t, params)
}

func TestBASE_X25519_SHA256_XChaCha20Blake2bSIV(t *testing.T) {
	params, err := GetParams(BASE_X25519_SHA256_XChaCha20Blake2bSIV)
	if err != nil {
		t.Error(err)
	}
	testBaseHPKE(t, params)
}

func TestBASE_P521_SHA256_XChaCha20Blake2bSIV(t *testing.T) {
	params, err := GetParams(BASE_P521_SHA256_XChaCha20Blake2bSIV)
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

	msg := make([]byte, 64)
	rand.Read(msg)
	aad := make([]byte, 16)
	rand.Read(aad)
	psk := make([]byte, 32)
	rand.Read(psk)
	pskId := make([]byte, 16)
	rand.Read(pskId)

	ct, ephemeral, err := EncryptPSK(params, random, pub, msg, aad, psk, pskId)
	if err != nil {
		t.Error(err)
	}

	pt, err := DecryptPSK(params, prv, ephemeral, ct, aad, psk, pskId)
	if err != nil {
		t.Error(err)
	}

	if !bytes.Equal(msg, pt) {
		t.Error("plaintext do not match")
	}

	malPsk := make([]byte, 32)
	rand.Read(malPsk)
	malPskId := make([]byte, 16)
	rand.Read(malPskId)
	_, err = DecryptPSK(params, prv, ephemeral, ct, aad, malPsk, malPskId)
	if err == nil {
		t.Error("different pre-shared key does not invalidate decryption")
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

func TestPSK_P256_SHA256_XChaCha20Blake2bSIV(t *testing.T) {
	params, err := GetParams(PSK_P256_SHA256_XChaCha20Blake2bSIV)
	if err != nil {
		t.Error(err)
	}
	testPSKHPKE(t, params)
}

func TestPSK_X25519_SHA256_XChaCha20Blake2bSIV(t *testing.T) {
	params, err := GetParams(PSK_X25519_SHA256_XChaCha20Blake2bSIV)
	if err != nil {
		t.Error(err)
	}
	testPSKHPKE(t, params)
}

func TestPSK_P521_SHA256_XChaCha20Blake2bSIV(t *testing.T) {
	params, err := GetParams(PSK_P521_SHA256_XChaCha20Blake2bSIV)
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

	msg := make([]byte, 64)
	rand.Read(msg)
	aad := make([]byte, 16)
	rand.Read(aad)

	ct, ephemeral, err := EncryptAuth(params, random, pkR, skI, msg, aad)
	if err != nil {
		t.Error(err)
	}

	pt, err := DecryptAuth(params, skR, pkI, ephemeral, ct, aad)
	if err != nil {
		t.Error(err)
	}

	if !bytes.Equal(msg, pt) {
		t.Error("plaintext do not match")
	}

	_, pub, err := GenerateKeyPair(params, random)
	if err != nil {
		t.Error(err)
	}
	_, err = DecryptAuth(params, skR, pub, ephemeral, ct, aad)
	if err == nil {
		t.Error("different initiator public key does not invalidate decryption")
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

func TestAUTH_P256_SHA256_XChaCha20Blake2bSIV(t *testing.T) {
	params, err := GetParams(AUTH_P256_SHA256_XChaCha20Blake2bSIV)
	if err != nil {
		t.Error(err)
	}
	testAuthHPKE(t, params)
}

func TestAUTH_X25519_SHA256_XChaCha20Blake2bSIV(t *testing.T) {
	params, err := GetParams(AUTH_X25519_SHA256_XChaCha20Blake2bSIV)
	if err != nil {
		t.Error(err)
	}
	testAuthHPKE(t, params)
}

func TestAUTH_P521_SHA256_XChaCha20Blake2bSIV(t *testing.T) {
	params, err := GetParams(AUTH_P521_SHA256_XChaCha20Blake2bSIV)
	if err != nil {
		t.Error(err)
	}
	testAuthHPKE(t, params)
}
