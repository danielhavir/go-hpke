![stability-wip](https://img.shields.io/badge/stability-work_in_progress-lightgrey.svg) ![tests-passing](https://danielhavir.github.io/badges/7b10a2ec99832a186dac8cc279a45d3e/tests_passing.svg)

# HPKE: Hybrid Public Key Encryption
This project implements the [CFRG](https://irtf.org/cfrg)'s [draft-barnes-cfrg-hpke-01](https://datatracker.ietf.org/doc/draft-barnes-cfrg-hpke/), Hybrid Public Key Encryption (HPKE). **This branch differs from the original draft** in the nonce generation for AEAD. Rather than stateful deriving of the nonce, this branch randomly generates the nonce and appends in the beggining of the ciphertext . For the original stateful implementation, look for branch `draft-01`.

## Authentication modes

Referenced from [section 6](https://tools.ietf.org/html/draft-barnes-cfrg-hpke-01#section-6):

* `BASE` Encryption to a Public Key: the most basic function of an HPKE scheme is to enable encryption for the holder of a given KEM private key.
* `PSK` Authentication using a Pre-Shared Key: This variant extends the base mechansism by allowing the recipient to authenticate that the sender possessed a given pre-shared key (PSK). We assume that both parties have been provisioned with both the PSK value "psk" and another octet string "pskID" that is used to identify which PSK should be used.
* `AUTH` Authentication using an Asymmetric Key: This variant extends the base mechansism by allowing the recipient to authenticate that the sender possessed a given KEM private key. In other words, only two people could have produced this secret, so if the recipient is one, then the sender must be the other.

## Ciphersuite configuration

| Configuration Name                        | DH Group      | KDF           | AEAD              |
|-------------------------------------------|---------------|---------------|-------------------|
| \<mode\>_X25519_SHA256_AES_GCM_128        | Curve25519    | HKDF-SHA256   | AES-GCM-128       |
| \<mode\>_X25519_SHA256_ChaCha20Poly1305   | Curve25519    | HKDF-SHA256   | ChaCha20Poly1305  |
| \<mode\>_X25519_SHA256_XChaCha20Blake2bSIV| Curve25519    | HKDF-SHA256   | XChaCha20Blake2b  |
| \<mode\>_P256_SHA256_AES_GCM_128          | P-256         | HKDF-SHA256   | AES-GCM-128       |
| \<mode\>_P256_SHA256_ChaCha20Poly1305     | P-256         | HKDF-SHA256   | ChaCha20Poly1305  |
| \<mode\>_P256_SHA256_XChaCha20Blake2bSIV  | P-256         | HKDF-SHA256   | XChaCha20Blake2b  |
| \<mode\>_P521_SHA512_AES_GCM_256          | P-521         | HKDF-SHA512   | AES-GCM-256       |
| \<mode\>_P521_SHA512_ChaCha20Poly1305     | P-521         | HKDF-SHA512   | ChaCha20Poly1305  |
| \<mode\>_P521_SHA256_XChaCha20Blake2bSIV  | P-521         | HKDF-SHA512   | XChaCha20Blake2b  |

See [section 6](https://tools.ietf.org/html/draft-barnes-cfrg-hpke-01#section-6) for reference.

On top of the AEAD primitives from the draft, implements one more (experimental) AEAD construction with [XChaCha20Blake2b in the synthetic IV](https://github.com/danielhavir/xchacha20blake2b) construction (i.e. no nonce)

Examples: BASE_X25519_SHA256_AES_GCM_128, PSK_P256_SHA256_ChaCha20Poly1305, AUTH_P521_SHA512_ChaCha20Poly1305

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
    params, _ := hpke.GetParams(hpke.BASE_X25519_SHA256_XChaCha20Blake2bSIV)
    
    random := rand.Reader
    prv, pub, err := hpke.GenerateKeypair(params, random)
    if err != nil {
        panic(fmt.Sprintf("failed to generate key pair: %s\n", err))
    }

    msg := ...

    ciphertext, ephemeral, err := hpke.EncryptBase(params, random, pub, msg, nil)
    if err != nil {
        panic(fmt.Sprintf("failed to encrypt message: %s\n", err))
    }

    plaintext, err := hpke.DecryptBase(params, prv, ephemeral, ciphertext, nil)
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
