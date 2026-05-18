// Package native contains C-reference-style Falcon/FN-DSA primitives.
//
// This package intentionally follows the native Rust implementation layout:
// codec, common, fpr, fft, keygen, rng, shake, sign, vrfy, and falcon wrapper
// functions. Public APIs in the parent package build on top of these helpers.
package native
