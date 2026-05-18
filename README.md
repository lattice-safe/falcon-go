# falcon-go

Native Go implementation of FN-DSA (FIPS 206), formerly Falcon.

This repository is being ported from the native Rust implementation at
`github.com/lattice-safe/falcon-rs`, pinned for compatibility work to commit
`d856a757f8ed6d0aaca1eed384ca8bfce52c6c47`.

## Current Status

- FN-DSA-512 and FN-DSA-1024 key generation
- Deterministic key generation for reproducible tests
- CT-format signing and verification
- FIPS 206 domain separation
- HashFN-DSA with SHA-256 and SHA-512
- Private/public key import and public-key recomputation
- Expanded-key compatible signing handle with one-time private-key decoding
- Public size helpers for key/signature allocation
- Native SHAKE256, Falcon codec helpers, hash-to-point, PRNG, and size tests
- Rust `falcon-rs` FIPS 206 fixture verification
- Byte-for-byte deterministic public-key and signature KATs against Rust
  `falcon-rs` FIPS 206 fixtures

Still in progress for complete low-level native parity:

- Rust-style low-level `falcon_*` API wrappers
- True LDL-tree expanded-key acceleration
- Full NIST transcript hash test port

## Quick Start

```go
kp, err := falcon.Generate(9) // FN-DSA-512
if err != nil {
    panic(err)
}

sig, err := kp.Sign([]byte("hello"), falcon.DomainNone())
if err != nil {
    panic(err)
}

err = falcon.Verify(sig.Bytes(), kp.PublicKey(), []byte("hello"), falcon.DomainNone())
```

## Sizes

```go
skLen, _ := falcon.PrivateKeySize(9)  // 1281
pkLen, _ := falcon.PublicKeySize(9)   // 897
sigLen, _ := falcon.SignatureSize(9)  // 809, CT format
```

## Attribution

The internal full FN-DSA core is adapted from Thomas Pornin's public-domain
`github.com/pornin/go-fn-dsa` implementation, with package-level changes for
the Rust `falcon-rs` FIPS 206 domain and CT-signature wire behavior. The
vendored public-domain notice is kept at `internal/fndsa/LICENSE`.
