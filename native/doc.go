// Package native provides C-reference-style Falcon/FN-DSA primitives.
//
// This package exposes the low-level API that mirrors the Falcon C reference
// implementation's function signatures. It is intended for applications that
// need fine-grained control over the signing pipeline, such as streamed
// message hashing via [Shake256Context] or transcript-recording semantics
// for reproducible test vectors.
//
// Most applications should use the high-level [falcon] package instead.
//
// # Streamed Signing
//
// The native API supports streamed signing where the message is absorbed
// incrementally:
//
//	var hd native.Shake256Context
//	native.FalconSignStart(&rng, nonce[:], &hd)
//	native.Shake256Inject(&hd, chunk1)
//	native.Shake256Inject(&hd, chunk2)
//	rc := native.FalconSignDynFinish(&rng, sig, &sigLen, native.SigCT, privkey, &hd, nonce[:], nil)
//
// # Signature Types
//
// Three signature encodings are supported:
//
//   - [SigCT]: constant-time format (header 0x50), recommended for side-channel resistance.
//   - [SigPadded]: padded compressed format (header 0x30), fixed-size.
//   - [SigCompressed]: variable-length compressed format (header 0x30, trailing zeros stripped).
package native
