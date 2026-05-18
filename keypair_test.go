package falcon

import (
	"crypto/rand"
	"errors"
	"testing"
)

type errReader struct{}

func (errReader) Read(p []byte) (n int, err error) {
	return 0, errors.New("reader error")
}

func TestKeyPairErrors(t *testing.T) {
	// Test Generate with random error
	oldReader := rand.Reader
	rand.Reader = errReader{}
	_, err := Generate(9)
	if err != ErrRandom {
		t.Fatalf("Generate(9) with broken rand.Reader expected ErrRandom, got: %v", err)
	}
	rand.Reader = oldReader

	// Test Generate with random
	kp, err := Generate(9)
	if err != nil {
		t.Fatalf("Generate(9) error: %v", err)
	}
	if kp.VariantName() != "FN-DSA-512" {
		t.Fatalf("VariantName() = %v, want FN-DSA-512", kp.VariantName())
	}
	if kp.LogN() != 9 {
		t.Fatalf("LogN() = %v, want 9", kp.LogN())
	}

	kp1024, _ := Generate(10)
	if kp1024.VariantName() != "FN-DSA-1024" {
		t.Fatalf("VariantName() = %v, want FN-DSA-1024", kp1024.VariantName())
	}

	// Test unknown variant name
	kpUnknown := &KeyPair{logn: 8}
	if kpUnknown.VariantName() != "FN-DSA-256" {
		t.Fatalf("VariantName() = %v, want FN-DSA-256", kpUnknown.VariantName())
	}

	// Test nil receiver
	var nilKp *KeyPair
	if nilKp.PrivateKey() != nil {
		t.Errorf("nilKp.PrivateKey() = %v, want nil", nilKp.PrivateKey())
	}
	if nilKp.PublicKey() != nil {
		t.Errorf("nilKp.PublicKey() = %v, want nil", nilKp.PublicKey())
	}
	if nilKp.LogN() != 0 {
		t.Errorf("nilKp.LogN() = %v, want 0", nilKp.LogN())
	}
	if nilKp.VariantName() != "FN-DSA-unknown" {
		t.Errorf("nilKp.VariantName() = %v, want FN-DSA-unknown", nilKp.VariantName())
	}

	// Test Generate invalid
	_, err = Generate(8)
	if err != ErrBadArgument {
		t.Fatalf("Generate(8) expected ErrBadArgument, got: %v", err)
	}

	// Test GenerateDeterministic invalid
	_, err = GenerateDeterministic(nil, 8)
	if err != ErrBadArgument {
		t.Fatalf("GenerateDeterministic(nil, 8) expected ErrBadArgument, got: %v", err)
	}

	// Test FromKeys
	kp2, err := FromKeys(kp.PrivateKey(), kp.PublicKey())
	if err != nil {
		t.Fatalf("FromKeys error: %v", err)
	}
	if string(kp2.PrivateKey()) != string(kp.PrivateKey()) {
		t.Fatalf("FromKeys PrivateKey mismatch")
	}
	if string(kp2.PublicKey()) != string(kp.PublicKey()) {
		t.Fatalf("FromKeys PublicKey mismatch")
	}

	// Test FromKeys invalid formats
	_, err = FromKeys(nil, kp.PublicKey())
	if err != ErrFormat {
		t.Fatalf("FromKeys with nil private key expected ErrFormat, got: %v", err)
	}
	
	// Bad prefix for private key
	badPrefixPriv := cloneBytes(kp.PrivateKey())
	badPrefixPriv[0] = 0x69
	_, err = FromKeys(badPrefixPriv, kp.PublicKey())
	if err != ErrFormat {
		t.Fatalf("FromKeys with bad private key prefix expected ErrFormat")
	}

	// Bad logn for private key
	badLognPriv := cloneBytes(kp.PrivateKey())
	badLognPriv[0] = 0x58
	_, err = FromKeys(badLognPriv, kp.PublicKey())
	if err != ErrBadArgument {
		t.Fatalf("FromKeys with bad private key logn expected ErrBadArgument")
	}

	// Bad prefix for public key
	badPrefixPub := cloneBytes(kp.PublicKey())
	badPrefixPub[0] = 0x19
	_, err = FromKeys(kp.PrivateKey(), badPrefixPub)
	if err != ErrFormat {
		t.Fatalf("FromKeys with bad public key prefix expected ErrFormat")
	}

	// Bad logn for public key
	badLognPub := cloneBytes(kp.PublicKey())
	badLognPub[0] = 0x08
	_, err = FromKeys(kp.PrivateKey(), badLognPub)
	if err != ErrBadArgument {
		t.Fatalf("FromKeys with bad public key logn expected ErrBadArgument")
	}

	// Test FromKeys logN mismatch
	_, err = FromKeys(kp.PrivateKey(), kp1024.PublicKey())
	if err != ErrFormat {
		t.Fatalf("FromKeys with logN mismatch expected ErrFormat, got %v", err)
	}

	// Mismatched public key (same size, wrong content)
	wrongPub := cloneBytes(kp.PublicKey())
	wrongPub[10] ^= 0xFF
	_, err = FromKeys(kp.PrivateKey(), wrongPub)
	if err != ErrFormat {
		t.Fatalf("FromKeys with wrong public key content expected ErrFormat")
	}

	// Test FromKeys invalid (bad sizes)
	_, err = FromKeys(kp.PrivateKey()[:10], kp.PublicKey())
	if err != ErrFormat {
		t.Fatalf("FromKeys with short private key expected ErrFormat, got: %v", err)
	}

	// Test PublicKeyFromPrivate
	pub, err := PublicKeyFromPrivate(kp.PrivateKey())
	if err != nil {
		t.Fatalf("PublicKeyFromPrivate error: %v", err)
	}
	if string(pub) != string(kp.PublicKey()) {
		t.Fatalf("PublicKeyFromPrivate mismatch")
	}

	// Test PublicKeyFromPrivate invalid
	_, err = PublicKeyFromPrivate(kp.PrivateKey()[:10])
	if err != ErrFormat {
		t.Fatalf("PublicKeyFromPrivate with short private key expected ErrFormat, got: %v", err)
	}
	
	// Test FromPrivateKey invalid
	_, err = FromPrivateKey(kp.PrivateKey()[:10])
	if err != ErrFormat {
		t.Fatalf("FromPrivateKey with short private key expected ErrFormat, got: %v", err)
	}

	// Test logNFromPublic with bad keys
	_, err = FromKeys(kp.PrivateKey(), []byte{0x00, 0x00}) // wrong logn
	if err == nil {
		t.Fatalf("FromKeys expected error for bad public logn")
	}

	// Test translateError
	// Internal coverage
	err = translateError(errors.New("falcon: bad argument"))
	if err != ErrFormat {
		t.Fatalf("translateError expected ErrFormat, got %v", err)
	}
	err = translateError(nil)
	if err != nil {
		t.Fatalf("translateError(nil) expected nil, got %v", err)
	}
}
