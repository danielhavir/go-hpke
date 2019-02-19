![stability-wip](https://img.shields.io/badge/stability-work_in_progress-lightgrey.svg)

# HPKE: Hybrid Public Key Encryption
This project implements the [CFRG](https://irtf.org/cfrg)'s [draft-barnes-cfrg-hpke-00](https://datatracker.ietf.org/doc/draft-barnes-cfrg-hpke/), Hybrid Public Key Encryption (HPKE).

## Ciphersuite configuration

| Configuration Name               | DH Group      | KDF           | AEAD              |
|----------------------------------|---------------|---------------|-------------------|
| X25519_SHA256_AES_GCM_128        | Curve25519    | HKDF-SHA256   | AES-GCM-128       |
| X25519_SHA256_ChaCha20Poly1305   | Curve25519    | HKDF-SHA256   | ChaCha20Poly1305  |
| P256_SHA256_AES_GCM_128          | P-256         | HKDF-SHA256   | AES-GCM-128       |
| P256_SHA256_ChaCha20Poly1305     | P-256         | HKDF-SHA256   | ChaCha20Poly1305  |
| P521_SHA512_AES_GCM_256          | P-521         | HKDF-SHA512   | AES-GCM-256       |
| P521_SHA512_ChaCha20Poly1305     | P-521         | HKDF-SHA512   | ChaCha20Poly1305  |

See [section 6](https://tools.ietf.org/html/draft-barnes-cfrg-hpke-00#section-6) for reference.

### Install
* Run `go get -u https://github.com/danielhavir/go-hpke`

## Example
```go
package main

import (
    "fmt"
    "crypto/rand"
    
    hpke "github.com/danielhavir/go-hpke"
)

func main() {
	params := hpke.X25519_SHA256_ChaCha20Poly1305

	prv, pub, err := hpke.GenerateKeypair(params)
	if err != nil {
		panic(fmt.Sprintf("failed to generate key pair: %s\n", err))
	}

	msg := ...

	ciphertext, ephemeral, err := hpke.Encrypt(params, rand.Reader, pub, msg, nil, nil)
	if err != nil {
		fmt.Sprintf("failed to encrypt message: %s\n", err)
	}

	plaintext, err := hpke.Decrypt(params, prv, ephemeral, ciphertext, nil, nil)
	if err != nil {
		panic(fmt.Sprintf("failed to decrypt ciphertext: %s\n", err))
	}

	if !bytes.Equal(msg, plaintext) {
		panic("authentication failed")
	} else {
		fmt.Println("all good")
	}
}
```

## References
* R. Barnes, K. Bhargavan - Hybrid Public Key Encryption [draft-barnes-cfrg-hpke-00](https://datatracker.ietf.org/doc/draft-barnes-cfrg-hpke/)
* Go [crypto package](https://godoc.org/golang.org/x/crypto)
* Go [ecdh package](https://godoc.org/github.com/aead/ecdh)
