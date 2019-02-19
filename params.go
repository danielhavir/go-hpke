package hpke

import (
	"crypto/elliptic"
	"crypto/sha256"
	"crypto/sha512"
	"hash"

	"github.com/aead/ecdh"
)

// Params is a struct for parameters
type Params struct {
	curve   ecdh.KeyExchange
	bitSize int
	hashFn  func() hash.Hash
	cipher  uint8
	nk      uint8
}

const (
	aes_gcm     = uint8(0)
	chacha_poly = uint8(1)
)

var (
	X25519_SHA256_AES_GCM_128 = &Params{
		curve:   ecdh.X25519(),
		bitSize: 256,
		hashFn:  sha256.New,
		cipher:  aes_gcm,
		nk:      16,
	}
	X25519_SHA256_ChaCha20Poly1305 = &Params{
		curve:   ecdh.X25519(),
		bitSize: 256,
		hashFn:  sha256.New,
		cipher:  chacha_poly,
		nk:      32,
	}
	P256_SHA256_AES_GCM_128 = &Params{
		curve:   ecdh.Generic(elliptic.P256()),
		bitSize: 256,
		hashFn:  sha256.New,
		cipher:  aes_gcm,
		nk:      16,
	}
	P256_SHA256_ChaCha20Poly1305 = &Params{
		curve:   ecdh.Generic(elliptic.P256()),
		bitSize: 256,
		hashFn:  sha256.New,
		cipher:  chacha_poly,
		nk:      32,
	}
	P521_SHA512_AES_GCM_256 = &Params{
		curve:   ecdh.Generic(elliptic.P521()),
		bitSize: 512,
		hashFn:  sha512.New,
		cipher:  aes_gcm,
		nk:      32,
	}
	P521_SHA512_ChaCha20Poly1305 = &Params{
		curve:   ecdh.Generic(elliptic.P521()),
		bitSize: 512,
		hashFn:  sha512.New,
		cipher:  chacha_poly,
		nk:      32,
	}
)
