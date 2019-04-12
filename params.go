package hpke

import (
	"crypto/elliptic"
	"crypto/sha256"
	"crypto/sha512"
	"errors"
	"hash"

	"github.com/aead/ecdh"
)

// Params is a struct for parameters
type Params struct {
	curve ecdh.KeyExchange
	//bitSize int
	hashFn      func() hash.Hash
	nk          uint8
	nh          uint8
	ciphersuite uint8
	mode        uint8
}

const (
	mode_base uint8 = iota
	mode_psk
	mode_auth
)

const (
	BASE_P256_SHA256_AES_GCM_128 byte = iota
	BASE_P256_SHA256_ChaCha20Poly1305
	PSK_P256_SHA256_AES_GCM_128
	PSK_P256_SHA256_ChaCha20Poly1305
	AUTH_P256_SHA256_AES_GCM_128
	AUTH_P256_SHA256_ChaCha20Poly1305
	BASE_X25519_SHA256_AES_GCM_128
	BASE_X25519_SHA256_ChaCha20Poly1305
	PSK_X25519_SHA256_AES_GCM_128
	PSK_X25519_SHA256_ChaCha20Poly1305
	AUTH_X25519_SHA256_AES_GCM_128
	AUTH_X25519_SHA256_ChaCha20Poly1305
	BASE_P521_SHA512_AES_GCM_256
	BASE_P521_SHA512_ChaCha20Poly1305
	PSK_P521_SHA512_AES_GCM_256
	PSK_P521_SHA512_ChaCha20Poly1305
	AUTH_P521_SHA512_AES_GCM_256
	AUTH_P521_SHA512_ChaCha20Poly1305

	BASE_P256_SHA256_XChaCha20Blake2bSIV
	PSK_P256_SHA256_XChaCha20Blake2bSIV
	AUTH_P256_SHA256_XChaCha20Blake2bSIV
	BASE_X25519_SHA256_XChaCha20Blake2bSIV
	PSK_X25519_SHA256_XChaCha20Blake2bSIV
	AUTH_X25519_SHA256_XChaCha20Blake2bSIV
	BASE_P521_SHA256_XChaCha20Blake2bSIV
	PSK_P521_SHA256_XChaCha20Blake2bSIV
	AUTH_P521_SHA256_XChaCha20Blake2bSIV
)

const nn = uint8(12)

func GetParams(mode byte) (*Params, error) {
	switch mode {
	case BASE_P256_SHA256_AES_GCM_128:
		return &Params{
			curve: ecdh.Generic(elliptic.P256()),
			// bitSize: 256,
			hashFn:      sha256.New,
			nk:          16,
			nh:          32,
			ciphersuite: 1,
			mode:        mode_base,
		}, nil
	case BASE_P256_SHA256_ChaCha20Poly1305:
		return &Params{
			curve: ecdh.Generic(elliptic.P256()),
			// bitSize: 256,
			hashFn:      sha256.New,
			nk:          32,
			nh:          32,
			ciphersuite: 2,
			mode:        mode_base,
		}, nil
	case BASE_P256_SHA256_XChaCha20Blake2bSIV:
		return &Params{
			curve: ecdh.Generic(elliptic.P256()),
			// bitSize: 256,
			hashFn:      sha256.New,
			nk:          64,
			nh:          32,
			ciphersuite: 7,
			mode:        mode_base,
		}, nil
	case PSK_P256_SHA256_AES_GCM_128:
		return &Params{
			curve: ecdh.Generic(elliptic.P256()),
			// bitSize: 256,
			hashFn:      sha256.New,
			nk:          16,
			nh:          32,
			ciphersuite: 1,
			mode:        mode_psk,
		}, nil
	case PSK_P256_SHA256_ChaCha20Poly1305:
		return &Params{
			curve: ecdh.Generic(elliptic.P256()),
			// bitSize: 256,
			hashFn:      sha256.New,
			nk:          32,
			nh:          32,
			ciphersuite: 2,
			mode:        mode_psk,
		}, nil
	case PSK_P256_SHA256_XChaCha20Blake2bSIV:
		return &Params{
			curve: ecdh.Generic(elliptic.P256()),
			// bitSize: 256,
			hashFn:      sha256.New,
			nk:          64,
			nh:          32,
			ciphersuite: 7,
			mode:        mode_psk,
		}, nil
	case AUTH_P256_SHA256_AES_GCM_128:
		return &Params{
			curve: ecdh.Generic(elliptic.P256()),
			// bitSize: 256,
			hashFn:      sha256.New,
			nk:          16,
			nh:          32,
			ciphersuite: 1,
			mode:        mode_auth,
		}, nil
	case AUTH_P256_SHA256_ChaCha20Poly1305:
		return &Params{
			curve: ecdh.Generic(elliptic.P256()),
			// bitSize: 256,
			hashFn:      sha256.New,
			nk:          32,
			nh:          32,
			ciphersuite: 2,
			mode:        mode_auth,
		}, nil
	case AUTH_P256_SHA256_XChaCha20Blake2bSIV:
		return &Params{
			curve: ecdh.Generic(elliptic.P256()),
			// bitSize: 256,
			hashFn:      sha256.New,
			nk:          64,
			nh:          32,
			ciphersuite: 7,
			mode:        mode_auth,
		}, nil
	case BASE_X25519_SHA256_AES_GCM_128:
		return &Params{
			curve: ecdh.X25519(),
			// bitSize: 256,
			hashFn:      sha256.New,
			nk:          16,
			nh:          32,
			ciphersuite: 3,
			mode:        mode_base,
		}, nil
	case BASE_X25519_SHA256_ChaCha20Poly1305:
		return &Params{
			curve: ecdh.X25519(),
			// bitSize: 256,
			hashFn:      sha256.New,
			nk:          32,
			nh:          32,
			ciphersuite: 4,
			mode:        mode_base,
		}, nil
	case BASE_X25519_SHA256_XChaCha20Blake2bSIV:
		return &Params{
			curve: ecdh.X25519(),
			// bitSize: 256,
			hashFn:      sha256.New,
			nk:          64,
			nh:          32,
			ciphersuite: 8,
			mode:        mode_base,
		}, nil
	case PSK_X25519_SHA256_AES_GCM_128:
		return &Params{
			curve: ecdh.X25519(),
			// bitSize: 256,
			hashFn:      sha256.New,
			nk:          16,
			nh:          32,
			ciphersuite: 3,
			mode:        mode_psk,
		}, nil
	case PSK_X25519_SHA256_ChaCha20Poly1305:
		return &Params{
			curve: ecdh.X25519(),
			// bitSize: 256,
			hashFn:      sha256.New,
			nk:          32,
			nh:          32,
			ciphersuite: 4,
			mode:        mode_psk,
		}, nil
	case PSK_X25519_SHA256_XChaCha20Blake2bSIV:
		return &Params{
			curve: ecdh.X25519(),
			// bitSize: 256,
			hashFn:      sha256.New,
			nk:          64,
			nh:          32,
			ciphersuite: 8,
			mode:        mode_psk,
		}, nil
	case AUTH_X25519_SHA256_AES_GCM_128:
		return &Params{
			curve: ecdh.X25519(),
			// bitSize: 256,
			hashFn:      sha256.New,
			nk:          16,
			nh:          32,
			ciphersuite: 3,
			mode:        mode_auth,
		}, nil
	case AUTH_X25519_SHA256_ChaCha20Poly1305:
		return &Params{
			curve: ecdh.X25519(),
			// bitSize: 256,
			hashFn:      sha256.New,
			nk:          32,
			nh:          32,
			ciphersuite: 4,
			mode:        mode_auth,
		}, nil
	case AUTH_X25519_SHA256_XChaCha20Blake2bSIV:
		return &Params{
			curve: ecdh.X25519(),
			// bitSize: 256,
			hashFn:      sha256.New,
			nk:          64,
			nh:          32,
			ciphersuite: 8,
			mode:        mode_auth,
		}, nil
	case BASE_P521_SHA512_AES_GCM_256:
		return &Params{
			curve:       ecdh.Generic(elliptic.P521()),
			hashFn:      sha512.New,
			nk:          32,
			nh:          64,
			ciphersuite: 5,
			mode:        mode_base,
		}, nil
	case BASE_P521_SHA512_ChaCha20Poly1305:
		return &Params{
			curve:       ecdh.Generic(elliptic.P521()),
			hashFn:      sha512.New,
			nk:          32,
			nh:          64,
			ciphersuite: 6,
			mode:        mode_base,
		}, nil
	case BASE_P521_SHA256_XChaCha20Blake2bSIV:
		return &Params{
			curve:       ecdh.Generic(elliptic.P521()),
			hashFn:      sha256.New,
			nk:          64,
			nh:          32,
			ciphersuite: 9,
			mode:        mode_base,
		}, nil
	case PSK_P521_SHA512_AES_GCM_256:
		return &Params{
			curve:       ecdh.Generic(elliptic.P521()),
			hashFn:      sha512.New,
			nk:          32,
			nh:          64,
			ciphersuite: 5,
			mode:        mode_psk,
		}, nil
	case PSK_P521_SHA512_ChaCha20Poly1305:
		return &Params{
			curve:       ecdh.Generic(elliptic.P521()),
			hashFn:      sha512.New,
			nk:          32,
			nh:          64,
			ciphersuite: 6,
			mode:        mode_psk,
		}, nil
	case PSK_P521_SHA256_XChaCha20Blake2bSIV:
		return &Params{
			curve:       ecdh.Generic(elliptic.P521()),
			hashFn:      sha256.New,
			nk:          64,
			nh:          32,
			ciphersuite: 9,
			mode:        mode_psk,
		}, nil
	case AUTH_P521_SHA512_AES_GCM_256:
		return &Params{
			curve:       ecdh.Generic(elliptic.P521()),
			hashFn:      sha512.New,
			nk:          32,
			nh:          64,
			ciphersuite: 5,
			mode:        mode_auth,
		}, nil
	case AUTH_P521_SHA512_ChaCha20Poly1305:
		return &Params{
			curve:       ecdh.Generic(elliptic.P521()),
			hashFn:      sha512.New,
			nk:          32,
			nh:          64,
			ciphersuite: 6,
			mode:        mode_auth,
		}, nil
	case AUTH_P521_SHA256_XChaCha20Blake2bSIV:
		return &Params{
			curve:       ecdh.Generic(elliptic.P521()),
			hashFn:      sha256.New,
			nk:          64,
			nh:          32,
			ciphersuite: 9,
			mode:        mode_auth,
		}, nil
	default:
		return nil, errors.New("unknown mode")
	}
}
