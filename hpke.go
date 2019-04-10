package hpke

import (
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"fmt"
	"hash"
	"io"
	"math/big"

	"github.com/aead/ecdh"
	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/hkdf"
)

// GenerateKeyPair generates a key pair for a given parameter set.
// Argument `random` is optional. If `nil` crypto/rand.Reader is used
func GenerateKeyPair(params *Params, random io.Reader) (private crypto.PrivateKey, public crypto.PublicKey, err error) {
	private, public, err = params.curve.GenerateKey(random)
	return
}

// Marshall produces a fixed-length octet string encoding the public key "pk" checks whether a generic
// interface matches the right type of a HPKE public key
// performs casting from crypto.PrivateKey to ecdh.Point (when using public key of generic curves)
// or byte array
// Reference 1: https://github.com/aead/ecdh/blob/master/generic.go#L99-L121
// Reference 2: https://github.com/aead/ecdh/blob/master/curve25519.go#L88-L108
func Marshall(key interface{}) (keyBytes []byte, err error) {
	switch t := key.(type) {
	case ecdh.Point:
		keyBytes = marshallGeneric(t)
	case *ecdh.Point:
		keyBytes = marshallGeneric(*t)
	case [32]byte:
		keyBytes = make([]byte, 32)
		copy(keyBytes[:], t[:])
	case *[32]byte:
		keyBytes = make([]byte, 32)
		copy(keyBytes[:], t[:])
	case []byte:
		if len(t) == 32 {
			keyBytes = make([]byte, 32)
			copy(keyBytes[:], t)
		} else {
			err = errors.New("incorrect key")
		}
	case *[]byte:
		if len(*t) == 32 {
			keyBytes = make([]byte, 32)
			copy(keyBytes[:], *t)
		} else {
			err = errors.New("incorrect key")
		}
	default:
		err = errors.New("incorrect key")
	}
	return
}

// helper function for marshalling a point on an elliptic curve into a byte array
func marshallGeneric(key ecdh.Point) (pubBytes []byte) {
	xBytes := uint8(len(key.X.Bytes()))
	yBytes := uint8(len(key.Y.Bytes()))
	pubBytes = make([]byte, 2+xBytes+yBytes)
	pubBytes[0] = xBytes
	pubBytes[1] = yBytes
	copy(pubBytes[2:xBytes+2], key.X.Bytes())
	copy(pubBytes[xBytes+2:], key.Y.Bytes())
	return
}

// Unmarshall parses a fixed-length octet string to recover a public keyrestores
// the public key from byte array after marshall
func Unmarshall(params *Params, keyBytes []byte) (pub crypto.PublicKey, err error) {
	switch params.ciphersuite {
	case 1, 2, 5, 6:
		pub = unmarshallGeneric(keyBytes)
	case 3, 4:
		if len(keyBytes) == 32 {
			pub = keyBytes
		} else {
			err = errors.New("unknown size")
		}
	default:
		err = errors.New("unknown ciphersuite")
	}
	return
}

// helper function for unmarshalling a point on an elliptic curve to a byte array
func unmarshallGeneric(pubBytes []byte) (key ecdh.Point) {
	xBytes := uint8(pubBytes[0])
	x := new(big.Int).SetBytes(pubBytes[2 : xBytes+2])
	y := new(big.Int).SetBytes(pubBytes[xBytes+2:])
	return ecdh.Point{X: x, Y: y}
}

// encap generates an ephemeral symmetric key and a fixed-length encapsulation of that key that can be decapsulated by
// the holder of the private key corresponding to pk
func encap(params *Params, pkR crypto.PublicKey, random io.Reader) (shared, enc []byte, err error) {
	skE, pkE, err := GenerateKeyPair(params, random)
	if err != nil {
		return
	}
	shared = params.curve.ComputeSecret(skE, pkR)
	enc, err = Marshall(pkE)
	return
}

// decap uses the private key "sk" to recover the ephemeral symmetric key from its encapsulated representation "enc"
func decap(params *Params, skR crypto.PrivateKey, enc []byte) (shared []byte, err error) {
	pkE, err := Unmarshall(params, enc)
	if err != nil {
		return
	}
	shared = params.curve.ComputeSecret(skR, pkE)
	return
}

// authEncap is same as Encap(), but the outputs encode an assurance that the ephemeral shared key is known
// only to the holder of the private key "skI"
func authEncap(params *Params, pkR crypto.PublicKey, skI crypto.PrivateKey, random io.Reader) (shared, enc []byte, err error) {
	skE, pkE, err := GenerateKeyPair(params, random)
	if err != nil {
		return
	}
	shared = append(params.curve.ComputeSecret(skE, pkR), params.curve.ComputeSecret(skI, pkR)...)
	enc, err = Marshall(pkE)
	return
}

// authDecap is same as Decap(), but the holder of the private key "skI" is assured that the ephemeral shared
// key is known only to the holder of the private key corresponding to "pkI"
func authDecap(params *Params, skR crypto.PrivateKey, pkI crypto.PublicKey, enc []byte) (shared []byte, err error) {
	pkE, err := Unmarshall(params, enc)
	if err != nil {
		return
	}
	shared = append(params.curve.ComputeSecret(skR, pkE), params.curve.ComputeSecret(skR, pkI)...)
	return
}

// setupCore is a function with the common part of the process in setting up the shared secret for different HPKE variants
// Section 6.1. https://tools.ietf.org/html/draft-barnes-cfrg-hpke-01#section-6.1
func setupCore(params *Params, mode byte, secret, kemContext, info []byte) (key, nonce []byte, err error) {
	context := make([]byte, 4+len(info)+len(kemContext))
	context[0] = params.ciphersuite
	context[1] = mode
	context[2] = uint8(len(kemContext))
	copy(context[3:3+len(kemContext)], kemContext)
	context[len(kemContext)+3] = uint8(len(info))
	copy(context[len(kemContext)+4:], info)

	key = make([]byte, params.nk)
	nonce = make([]byte, nn)
	if _, err = hkdf.Expand(params.hashFn, secret, append([]byte("hpke key"), context...)).Read(key); err != nil {
		return
	}
	_, err = hkdf.Expand(params.hashFn, secret, append([]byte("hpke nonce"), context...)).Read(nonce)
	return
}

// setupBase is the common setup in the base mode for the Initiator and the Receiver
// Section 6.1. https://tools.ietf.org/html/draft-barnes-cfrg-hpke-01#section-6.1
func setupBase(params *Params, pkR crypto.PublicKey, shared, enc, info []byte) (key, nonce []byte, err error) {
	pkRBytes, err := Marshall(pkR)
	if err != nil {
		err = errors.New("incorrect receiver's public key")
		return
	}
	kemContext := append(enc, pkRBytes...)
	secret := hkdf.Extract(params.hashFn, shared, make([]byte, params.nh))
	return setupCore(params, mode_base, secret, kemContext, info)
}

// setupPSK is the common setup in the psk mode for the Initiator and the Receiver
// Section 6.2. https://tools.ietf.org/html/draft-barnes-cfrg-hpke-01#section-6.2
func setupPSK(params *Params, pkR crypto.PublicKey, psk, pskID, shared, enc, info []byte) (key, nonce []byte, err error) {
	pkRBytes, err := Marshall(pkR)
	if err != nil {
		err = errors.New("incorrect receiver's public key")
		return
	}
	kemContext := append(enc, pkRBytes...)
	kemContext = append(kemContext, pskID...)
	secret := hkdf.Extract(params.hashFn, shared, psk)
	return setupCore(params, mode_psk, secret, kemContext, info)
}

// setupAuth is the common setup in the auth mode for the Initiator and the Receiver
// Section 6.3. https://tools.ietf.org/html/draft-barnes-cfrg-hpke-01#section-6.3
func setupAuth(params *Params, pkR, pkI crypto.PublicKey, shared, enc, info []byte) (key, nonce []byte, err error) {
	// TODO: kemContext := append(pkE, pkR, pkI...)
	pkRBytes, err := Marshall(pkR)
	if err != nil {
		err = errors.New("incorrect receiver's public key")
		return
	}
	pkIBytes, err := Marshall(pkI)
	if err != nil {
		err = errors.New("incorrect initiator's public key")
		return
	}
	kemContext := append(enc, pkRBytes...)
	kemContext = append(kemContext, pkIBytes...)
	secret := hkdf.Extract(params.hashFn, shared, make([]byte, params.nh))
	return setupCore(params, mode_auth, secret, kemContext, info)
}

// setupBaseI is the setup for the Initiator in the base mode
// Section 6.1. https://tools.ietf.org/html/draft-barnes-cfrg-hpke-01#section-6.1
func setupBaseI(params *Params, pkR crypto.PublicKey, random io.Reader, info []byte) (key, nonce []byte, err error) {
	shared, enc, err := encap(params, pkR, random)
	if err != nil {
		return
	}
	return setupBase(params, pkR, shared, enc, info)
}

// setupBaseR is the setup for the Receiver in the base mode
// Section 6.1. https://tools.ietf.org/html/draft-barnes-cfrg-hpke-01#section-6.1
func setupBaseR(params *Params, skR crypto.PrivateKey, enc, info []byte) (key, nonce []byte, err error) {
	shared, err := decap(params, skR, enc)
	if err != nil {
		return
	}
	return setupBase(params, params.curve.PublicKey(skR), shared, enc, info)
}

// setupPSKI is the setup for the Initiator in the psk mode
// Section 6.2. https://tools.ietf.org/html/draft-barnes-cfrg-hpke-01#section-6.2
func setupPSKI(params *Params, pkR crypto.PublicKey, random io.Reader, psk, pskID, info []byte) (key, nonce []byte, err error) {
	shared, enc, err := encap(params, pkR, random)
	if err != nil {
		return
	}
	return setupPSK(params, pkR, psk, pskID, shared, enc, info)
}

// setupPskR is the setup for the Receiver in the psk mode
// Section 6.2. https://tools.ietf.org/html/draft-barnes-cfrg-hpke-01#section-6.2
func setupPskR(params *Params, skR crypto.PrivateKey, enc, psk, pskID, info []byte) (key, nonce []byte, err error) {
	shared, err := decap(params, skR, enc)
	if err != nil {
		return
	}
	return setupPSK(params, params.curve.PublicKey(skR), psk, pskID, shared, enc, info)
}

// setupAuthI is the setup for the Initiator in the auth mode
// Section 6.3. https://tools.ietf.org/html/draft-barnes-cfrg-hpke-01#section-6.3
func setupAuthI(params *Params, pkR crypto.PublicKey, skI crypto.PrivateKey, random io.Reader, info []byte) (key, nonce []byte, err error) {
	shared, enc, err := authEncap(params, pkR, skI, random)
	if err != nil {
		return
	}
	return setupAuth(params, pkR, params.curve.PublicKey(skI), shared, enc, info)
}

// setupAuthR is the setup for the Receiver in the auth mode
// Section 6.3. https://tools.ietf.org/html/draft-barnes-cfrg-hpke-01#section-6.3
func setupAuthR(params *Params, skR crypto.PrivateKey, pkI crypto.PublicKey, enc, info []byte) (key, nonce []byte, err error) {
	shared, err := authDecap(params, skR, pkI, enc)
	if err != nil {
		return
	}
	return setupAuth(params, params.curve.PublicKey(skR), pkI, shared, enc, info)
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
	fmt.Println("shared len: ", len(shared))
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
