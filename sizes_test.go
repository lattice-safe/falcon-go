package falcon

import (
	"testing"
)

func TestSizes(t *testing.T) {
	validLogNs := []uint{9, 10}
	invalidLogNs := []uint{0, 1, 8, 11, 12}

	for _, logn := range validLogNs {
		if _, err := PrivateKeySize(logn); err != nil {
			t.Errorf("PrivateKeySize(%d) unexpected error: %v", logn, err)
		}
		if _, err := PublicKeySize(logn); err != nil {
			t.Errorf("PublicKeySize(%d) unexpected error: %v", logn, err)
		}
		if _, err := SignatureSize(logn); err != nil {
			t.Errorf("SignatureSize(%d) unexpected error: %v", logn, err)
		}
		if _, err := PaddedSignatureSize(logn); err != nil {
			t.Errorf("PaddedSignatureSize(%d) unexpected error: %v", logn, err)
		}
	}

	for _, logn := range invalidLogNs {
		if _, err := PrivateKeySize(logn); err != ErrBadArgument {
			t.Errorf("PrivateKeySize(%d) expected ErrBadArgument, got %v", logn, err)
		}
		if _, err := PublicKeySize(logn); err != ErrBadArgument {
			t.Errorf("PublicKeySize(%d) expected ErrBadArgument, got %v", logn, err)
		}
		if _, err := SignatureSize(logn); err != ErrBadArgument {
			t.Errorf("SignatureSize(%d) expected ErrBadArgument, got %v", logn, err)
		}
		if _, err := PaddedSignatureSize(logn); err != ErrBadArgument {
			t.Errorf("PaddedSignatureSize(%d) expected ErrBadArgument, got %v", logn, err)
		}
	}
}
