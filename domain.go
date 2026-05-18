package falcon

import (
	"crypto/sha256"
	"crypto/sha512"
)

// PreHashAlgorithm selects the hash used by HashFN-DSA.
type PreHashAlgorithm uint8

const (
	// PreHashSHA256 selects SHA-256 for HashFN-DSA.
	PreHashSHA256 PreHashAlgorithm = iota + 1
	// PreHashSHA512 selects SHA-512 for HashFN-DSA.
	PreHashSHA512
)

var (
	// ASN.1 DER OID for id-sha256 (2.16.840.1.101.3.4.2.1).
	oidSHA256 = []byte{0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01}
	// ASN.1 DER OID for id-sha512 (2.16.840.1.101.3.4.2.3).
	oidSHA512 = []byte{0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x03}
)

// Domain captures the FIPS 206 domain separation mode used for signing.
type Domain struct {
	context []byte
	alg     PreHashAlgorithm
	prehash bool
}

// DomainNone returns pure FN-DSA with no context.
func DomainNone() Domain {
	return Domain{}
}

// DomainContext returns pure FN-DSA bound to an application context.
func DomainContext(ctx []byte) (Domain, error) {
	if len(ctx) > 255 {
		return Domain{}, ErrBadArgument
	}
	return Domain{context: cloneBytes(ctx)}, nil
}

// DomainPrehashed returns HashFN-DSA with the selected pre-hash algorithm.
func DomainPrehashed(alg PreHashAlgorithm, ctx []byte) (Domain, error) {
	if len(ctx) > 255 {
		return Domain{}, ErrBadArgument
	}
	if alg != PreHashSHA256 && alg != PreHashSHA512 {
		return Domain{}, ErrBadArgument
	}
	return Domain{context: cloneBytes(ctx), alg: alg, prehash: true}, nil
}

func (d Domain) validate() error {
	if len(d.context) > 255 {
		return ErrBadArgument
	}
	if d.prehash && d.alg != PreHashSHA256 && d.alg != PreHashSHA512 {
		return ErrBadArgument
	}
	return nil
}

func (d Domain) phFlag() byte {
	if d.prehash {
		return 0x01
	}
	return 0x00
}

func (d Domain) oid() []byte {
	switch d.alg {
	case PreHashSHA256:
		return oidSHA256
	case PreHashSHA512:
		return oidSHA512
	default:
		return nil
	}
}

func (d Domain) messageForHash(message []byte) []byte {
	if !d.prehash {
		return message
	}
	switch d.alg {
	case PreHashSHA256:
		h := sha256.Sum256(message)
		return h[:]
	case PreHashSHA512:
		h := sha512.Sum512(message)
		return h[:]
	default:
		return nil
	}
}

func cloneBytes(src []byte) []byte {
	if len(src) == 0 {
		return nil
	}
	dst := make([]byte, len(src))
	copy(dst, src)
	return dst
}
