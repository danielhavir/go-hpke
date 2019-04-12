package hpke

import (
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"errors"
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
func Marshall(params *Params, key interface{}) (keyBytes []byte, err error) {
	switch t := key.(type) {
	case ecdh.Point:
		keyBytes = marshallGeneric(t, (params.curve.Params().BitSize+7)>>3)
	case *ecdh.Point:
		keyBytes = marshallGeneric(*t, (params.curve.Params().BitSize+7)>>3)
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
func marshallGeneric(key ecdh.Point, byteSize int) (pubBytes []byte) {
	pubBytes = make([]byte, 2*byteSize)
	offset := byteSize - len(key.X.Bytes())
	copy(pubBytes[offset:byteSize], key.X.Bytes())
	offset = byteSize - len(key.Y.Bytes())
	copy(pubBytes[byteSize+offset:], key.Y.Bytes())
	return
}

// Unmarshall parses a fixed-length octet string to recover a public keyrestores
// the public key from byte array after marshall
func Unmarshall(params *Params, keyBytes []byte) (pub crypto.PublicKey, err error) {
	switch params.ciphersuite {
	case 1, 2, 5, 6:
		pub = unmarshallGeneric(keyBytes, (params.curve.Params().BitSize+7)>>3)
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
func unmarshallGeneric(pubBytes []byte, byteSize int) (key ecdh.Point) {
	x := new(big.Int).SetBytes(pubBytes[:byteSize])
	y := new(big.Int).SetBytes(pubBytes[byteSize:])
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
	enc, err = Marshall(params, pkE)
	return
}

// decap uses the private key "sk" to recover the ephemeral symmetric key from its encapsulated representation "enc"
func decap(params *Params, skR crypto.PrivateKey, enc []byte) (shared []byte, err error) {
	pkE, err := Unmarshall(params, enc)
	if err != nil {
		return
	}
	if err = params.curve.Check(pkE); err != nil {
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
	enc, err = Marshall(params, pkE)
	return
}

// authDecap is same as Decap(), but the holder of the private key "skI" is assured that the ephemeral shared
// key is known only to the holder of the private key corresponding to "pkI"
func authDecap(params *Params, skR crypto.PrivateKey, pkI crypto.PublicKey, enc []byte) (shared []byte, err error) {
	pkE, err := Unmarshall(params, enc)
	if err != nil {
		return
	}
	if err = params.curve.Check(pkE); err != nil {
		return
	}
	shared = append(params.curve.ComputeSecret(skR, pkE), params.curve.ComputeSecret(skR, pkI)...)
	return
}

// setupCore is a function with the common part of the process in setting up the shared secret for different HPKE variants
// Section 6.1. https://tools.ietf.org/html/draft-barnes-cfrg-hpke-01#section-6.1
func setupCore(params *Params, mode byte, secret, kemContext []byte) (key []byte, err error) {
	context := make([]byte, 3+len(kemContext))
	context[0] = params.ciphersuite
	context[1] = mode
	context[2] = uint8(len(kemContext))
	copy(context[3:3+len(kemContext)], kemContext)

	key = make([]byte, params.nk)
	_, err = hkdf.Expand(params.hashFn, secret, append([]byte("hpke key"), context...)).Read(key)
	return
}

// setupBase is the common setup in the base mode for the Initiator and the Receiver
// Section 6.1. https://tools.ietf.org/html/draft-barnes-cfrg-hpke-01#section-6.1
func setupBase(params *Params, pkR crypto.PublicKey, shared, enc []byte) (key []byte, err error) {
	pkRBytes, err := Marshall(params, pkR)
	if err != nil {
		err = errors.New("incorrect receiver's public key")
		return
	}
	kemContext := append(enc, pkRBytes...)
	secret := hkdf.Extract(params.hashFn, shared, make([]byte, params.nh))
	return setupCore(params, mode_base, secret, kemContext)
}

// setupPSK is the common setup in the psk mode for the Initiator and the Receiver
// Section 6.2. https://tools.ietf.org/html/draft-barnes-cfrg-hpke-01#section-6.2
func setupPsk(params *Params, pkR crypto.PublicKey, psk, pskID, shared, enc []byte) (key []byte, err error) {
	pkRBytes, err := Marshall(params, pkR)
	if err != nil {
		err = errors.New("incorrect receiver's public key")
		return
	}
	kemContext := append(enc, pkRBytes...)
	kemContext = append(kemContext, pskID...)
	secret := hkdf.Extract(params.hashFn, shared, psk)
	return setupCore(params, mode_psk, secret, kemContext)
}

// setupAuth is the common setup in the auth mode for the Initiator and the Receiver
// Section 6.3. https://tools.ietf.org/html/draft-barnes-cfrg-hpke-01#section-6.3
func setupAuth(params *Params, pkR, pkI crypto.PublicKey, shared, enc []byte) (key []byte, err error) {
	// TODO: kemContext := append(pkE, pkR, pkI...)
	pkRBytes, err := Marshall(params, pkR)
	if err != nil {
		err = errors.New("incorrect receiver's public key")
		return
	}
	pkIBytes, err := Marshall(params, pkI)
	if err != nil {
		err = errors.New("incorrect initiator's public key")
		return
	}
	kemContext := append(enc, pkRBytes...)
	kemContext = append(kemContext, pkIBytes...)
	secret := hkdf.Extract(params.hashFn, shared, make([]byte, params.nh))
	return setupCore(params, mode_auth, secret, kemContext)
}

// setupBaseI is the setup for the Initiator in the base mode
// Section 6.1. https://tools.ietf.org/html/draft-barnes-cfrg-hpke-01#section-6.1
func setupBaseI(params *Params, pkR crypto.PublicKey, random io.Reader) (key, enc []byte, err error) {
	shared, enc, err := encap(params, pkR, random)
	if err != nil {
		return
	}
	key, err = setupBase(params, pkR, shared, enc)
	return
}

// setupBaseR is the setup for the Receiver in the base mode
// Section 6.1. https://tools.ietf.org/html/draft-barnes-cfrg-hpke-01#section-6.1
func setupBaseR(params *Params, skR crypto.PrivateKey, enc []byte) (key []byte, err error) {
	shared, err := decap(params, skR, enc)
	if err != nil {
		return
	}
	return setupBase(params, params.curve.PublicKey(skR), shared, enc)
}

// setupPSKI is the setup for the Initiator in the psk mode
// Section 6.2. https://tools.ietf.org/html/draft-barnes-cfrg-hpke-01#section-6.2
func setupPskI(params *Params, pkR crypto.PublicKey, random io.Reader, psk, pskID []byte) (key, enc []byte, err error) {
	shared, enc, err := encap(params, pkR, random)
	if err != nil {
		return
	}
	key, err = setupPsk(params, pkR, psk, pskID, shared, enc)
	return
}

// setupPskR is the setup for the Receiver in the psk mode
// Section 6.2. https://tools.ietf.org/html/draft-barnes-cfrg-hpke-01#section-6.2
func setupPskR(params *Params, skR crypto.PrivateKey, enc, psk, pskID []byte) (key []byte, err error) {
	shared, err := decap(params, skR, enc)
	if err != nil {
		return
	}
	return setupPsk(params, params.curve.PublicKey(skR), psk, pskID, shared, enc)
}

// setupAuthI is the setup for the Initiator in the auth mode
// Section 6.3. https://tools.ietf.org/html/draft-barnes-cfrg-hpke-01#section-6.3
func setupAuthI(params *Params, pkR crypto.PublicKey, skI crypto.PrivateKey, random io.Reader) (key, enc []byte, err error) {
	shared, enc, err := authEncap(params, pkR, skI, random)
	if err != nil {
		return
	}
	key, err = setupAuth(params, pkR, params.curve.PublicKey(skI), shared, enc)
	return

}

// setupAuthR is the setup for the Receiver in the auth mode
// Section 6.3. https://tools.ietf.org/html/draft-barnes-cfrg-hpke-01#section-6.3
func setupAuthR(params *Params, skR crypto.PrivateKey, pkI crypto.PublicKey, enc []byte) (key []byte, err error) {
	shared, err := authDecap(params, skR, pkI, enc)
	if err != nil {
		return
	}
	return setupAuth(params, params.curve.PublicKey(skR), pkI, shared, enc)
}

// return the appropriate aead ciphersuite based on params
func getAead(params *Params, key []byte) (cphr cipher.AEAD, err error) {
	switch params.ciphersuite {
	case 1, 3, 5:
		block, err := aes.NewCipher(key)
		if err != nil {
			return nil, err
		}
		cphr, err = cipher.NewGCM(block)
		if err != nil {
			return nil, err
		}
	case 2, 4, 6:
		cphr, err = chacha20poly1305.New(key)
		if err != nil {
			return
		}
	default:
		err = errors.New("unknown cipher choice")
		return
	}
	return
}

// xorNonce XORs the derived nonce with y-byte string containing the binary representation
// of state counter seq in big-endian byte order.
// this function is optimized so that the xor is performed simultaneously with the big endian encoding
func xorNonce(nonce []byte, seq, nonceSize int) []byte {
	useq := uint64(seq)
	var xByte byte
	for i := nonceSize - 1; i >= 0; i-- {
		xByte = byte(useq)
		nonce[i] ^= (xByte & 0xff)
		useq = useq >> 8
	}
	return nonce
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

// EncryptBase is a function for encryption in the base mode
// Optional arguments:
//    `random` is optional. If `nil` crypto/rand.Reader is used
//    `aad` and `info` are optional.
func EncryptBase(params *Params, random io.Reader, pkR crypto.PublicKey, pt, aad []byte) (ct, enc []byte, err error) {
	if params.mode != mode_base {
		err = errors.New("params specify different mode")
		return
	}

	if random == nil {
		random = rand.Reader
	}

	key, enc, err := setupBaseI(params, pkR, random)
	if err != nil {
		return
	}

	cphr, err := getAead(params, key)
	if err != nil {
		return
	}

	ct, err = encryptSymmetric(random, cphr, pt, aad)
	if err != nil {
		return
	}
	return
}

// DecryptBase is a function for decryption in the base mode
func DecryptBase(params *Params, skR crypto.PrivateKey, enc, ct, aad []byte) (pt []byte, err error) {
	if params.mode != mode_base {
		err = errors.New("params specify different mode")
		return
	}

	key, err := setupBaseR(params, skR, enc)

	cphr, err := getAead(params, key)
	if err != nil {
		return
	}

	pt, err = decryptSymmetric(cphr, ct, aad)
	if err != nil {
		return
	}
	return
}

// EncryptPSK is a function for encryption in the pre-shared key mode
// Optional arguments:
//    `random` is optional. If `nil` crypto/rand.Reader is used
//    `aad` and `info` are optional.
func EncryptPSK(params *Params, random io.Reader, pkR crypto.PublicKey, pt, aad, psk, pskID []byte) (ct, enc []byte, err error) {
	if params.mode != mode_psk {
		err = errors.New("params specify different mode")
		return
	}

	if random == nil {
		random = rand.Reader
	}

	key, enc, err := setupPskI(params, pkR, random, psk, pskID)
	if err != nil {
		return
	}

	cphr, err := getAead(params, key)
	if err != nil {
		return
	}

	ct, err = encryptSymmetric(random, cphr, pt, aad)
	if err != nil {
		return
	}
	return
}

// DecryptPSK is a function for decryption in the pre-shared key mode
func DecryptPSK(params *Params, skR crypto.PrivateKey, enc, ct, aad, psk, pskID []byte) (pt []byte, err error) {
	if params.mode != mode_psk {
		err = errors.New("params specify different mode")
		return
	}

	key, err := setupPskR(params, skR, enc, psk, pskID)

	cphr, err := getAead(params, key)
	if err != nil {
		return
	}

	pt, err = decryptSymmetric(cphr, ct, aad)
	if err != nil {
		return
	}
	return
}

// EncryptAuth is a function for encryption in the asymmetric key mode
// Optional arguments:
//    `random` is optional. If `nil` crypto/rand.Reader is used
//    `aad` and `info` are optional.
func EncryptAuth(params *Params, random io.Reader, pkR crypto.PublicKey, skI crypto.PrivateKey, pt, aad []byte) (ct, enc []byte, err error) {
	if params.mode != mode_auth {
		err = errors.New("params specify different mode")
		return
	}

	if random == nil {
		random = rand.Reader
	}

	key, enc, err := setupAuthI(params, pkR, skI, random)
	if err != nil {
		return
	}

	cphr, err := getAead(params, key)
	if err != nil {
		return
	}

	ct, err = encryptSymmetric(random, cphr, pt, aad)
	if err != nil {
		return
	}
	return
}

// DecryptAuth is a function for decryption in the asymmetric key mode
func DecryptAuth(params *Params, skR crypto.PrivateKey, pkI crypto.PublicKey, enc, ct, aad []byte) (pt []byte, err error) {
	if params.mode != mode_auth {
		err = errors.New("params specify different mode")
		return
	}

	key, err := setupAuthR(params, skR, pkI, enc)

	cphr, err := getAead(params, key)
	if err != nil {
		return
	}

	pt, err = decryptSymmetric(cphr, ct, aad)
	if err != nil {
		return
	}
	return
}
