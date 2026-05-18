package falcon

import "github.com/lattice-safe/falcon-go/internal/fndsa"

// PrivateKeySize returns the encoded private key size for a FIPS logn.
func PrivateKeySize(logn uint) (int, error) {
	if !isFIPSLogN(logn) {
		return 0, ErrBadArgument
	}
	return fndsa.SigningKeySize(logn), nil
}

// PublicKeySize returns the encoded public key size for a FIPS logn.
func PublicKeySize(logn uint) (int, error) {
	if !isFIPSLogN(logn) {
		return 0, ErrBadArgument
	}
	return fndsa.VerifyingKeySize(logn), nil
}

// SignatureSize returns the CT-format signature size for a FIPS logn.
func SignatureSize(logn uint) (int, error) {
	if !isFIPSLogN(logn) {
		return 0, ErrBadArgument
	}
	switch logn {
	case 9:
		return 809, nil
	case 10:
		return 1577, nil
	default:
		return 0, ErrBadArgument
	}
}

// PaddedSignatureSize returns the FIPS/Rust padded signature size.
func PaddedSignatureSize(logn uint) (int, error) {
	if !isFIPSLogN(logn) {
		return 0, ErrBadArgument
	}
	return fndsa.SignatureSize(logn), nil
}
