package hpke

import (
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"hash"
	"io"

	"golang.org/x/crypto/chacha20poly1305"
)

// GenerateKeypair generates a key pair for a given parameter set.
// Argument `random` is optional. If `nil` crypto/rand.Reader is used
func GenerateKeypair(params *Params, random io.Reader) (private crypto.PrivateKey, public crypto.PublicKey, err error) {
	private, public, err = params.curve.GenerateKey(random)
	return
}

// Key-Derivation Function
func kdf(params *Params, hash hash.Hash, shared, salt []byte) []byte {
	hash.Write(shared)
	if salt != nil {
		hash.Write(salt)
	}
	key := hash.Sum(nil)
	hash.Reset()
	return key[:params.nk]
}

// return the appropriate aead ciphersuite based on params
func getAead(params *Params, key []byte) (cphr cipher.AEAD, err error) {
	if params.cipher == aes_gcm {
		block, err := aes.NewCipher(key)
		if err != nil {
			return nil, err
		}
		cphr, err = cipher.NewGCM(block)
		if err != nil {
			return nil, err
		}
	} else if params.cipher == chacha_poly {
		cphr, err = chacha20poly1305.New(key)
		if err != nil {
			return nil, err
		}
	} else {
		return nil, errors.New("unknown cipher choice")
	}
	return
}

func encryptSymmetric(rand io.Reader, cphr cipher.AEAD, pt, aad []byte) (ct []byte, err error) {
	nonce := make([]byte, cphr.NonceSize())
	_, err = io.ReadFull(rand, nonce)
	if err != nil {
		return
	}
	ct = cphr.Seal(nil, nonce, pt, aad)
	ct = append(nonce, ct...)
	return
}

func decryptSymmetric(cphr cipher.AEAD, ct, aad []byte) (pt []byte, err error) {
	nonce := ct[:cphr.NonceSize()]
	pt, err = cphr.Open(nil, nonce, ct[cphr.NonceSize():], aad)
	return
}

// Encrypt is a function for encryption
// Optional arguments:
//    `random` is optional. If `nil` crypto/rand.Reader is used
//    `aad` and `salt` are optional.
func Encrypt(params *Params, random io.Reader, pkR crypto.PublicKey, pt, aad, salt []byte) (ct []byte, pkE crypto.PublicKey, err error) {
	if random == nil {
		random = rand.Reader
	}

	skE, pkE, err := params.curve.GenerateKey(random)
	if err != nil {
		return
	}

	hashFunc := params.hashFn()
	keySize := hashFunc.Size() / 2
	if 2*keySize > (params.curve.Params().BitSize+7)>>3 {
		err = errors.New("shared key length is too long")
		return
	}

	shared := params.curve.ComputeSecret(skE, pkR)
	K := kdf(params, hashFunc, shared, salt)

	cphr, err := getAead(params, K)
	if err != nil {
		return
	}
	ct, err = encryptSymmetric(random, cphr, pt, aad)
	if err != nil {
		return
	}
	return
}

// Decrypt is a function for decryption
func Decrypt(params *Params, skR crypto.PrivateKey, pkE crypto.PublicKey, ct, aad, salt []byte) (pt []byte, err error) {
	hashFunc := params.hashFn()
	keySize := hashFunc.Size() / 2
	if 2*keySize > (params.curve.Params().BitSize+7)>>3 {
		err = errors.New("shared key length is too long")
		return
	}

	err = params.curve.Check(pkE)
	if err != nil {
		return
	}

	shared := params.curve.ComputeSecret(skR, pkE)
	K := kdf(params, hashFunc, shared, salt)

	cphr, err := getAead(params, K)
	if err != nil {
		return
	}
	pt, err = decryptSymmetric(cphr, ct, aad)
	if err != nil {
		return
	}
	return
}
