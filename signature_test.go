package falcon

import (
	"crypto/rand"
	"testing"
)

func TestSignatureErrors(t *testing.T) {
	kp, _ := Generate(9)
	msg := []byte("hello")
	sig, _ := kp.Sign(msg, DomainNone())

	// Test FromSignatureBytes success
	sig2, err := FromSignatureBytes(sig.Bytes())
	if err != nil {
		t.Fatalf("FromSignatureBytes error: %v", err)
	}
	if string(sig2.Bytes()) != string(sig.Bytes()) {
		t.Fatalf("FromSignatureBytes mismatch")
	}
	if sig2.Len() != sig.Len() {
		t.Fatalf("Len mismatch")
	}

	// Test FromSignatureBytes invalid
	_, err = FromSignatureBytes(sig.Bytes()[:10])
	if err != ErrFormat {
		t.Fatalf("FromSignatureBytes short expected ErrFormat, got %v", err)
	}

	badHdr := cloneBytes(sig.Bytes())
	badHdr[0] = 0x99 // Invalid header
	_, err = FromSignatureBytes(badHdr)
	if err != ErrFormat {
		t.Fatalf("FromSignatureBytes bad hdr expected ErrFormat, got %v", err)
	}

	badLogn := cloneBytes(sig.Bytes())
	badLogn[0] = 0x58 // Valid header (0x50) but bad logn (8)
	_, err = FromSignatureBytes(badLogn)
	if err != ErrBadArgument {
		t.Fatalf("FromSignatureBytes bad logn expected ErrBadArgument, got %v", err)
	}

	// Test Sign with broken rand
	oldReader := rand.Reader
	rand.Reader = errReader{}
	_, err = kp.Sign(msg, DomainNone())
	if err != ErrRandom {
		t.Fatalf("Sign with broken rand.Reader expected ErrRandom, got %v", err)
	}
	rand.Reader = oldReader

	// Test SignDeterministic invalid kp
	var nilKp *KeyPair
	_, err = nilKp.SignDeterministic(msg, []byte("seed"), DomainNone())
	if err != ErrBadArgument {
		t.Fatalf("nilKp.SignDeterministic expected ErrBadArgument, got %v", err)
	}

	// Test Verify invalid inputs
	if err := Verify(nil, kp.PublicKey(), msg, DomainNone()); err != ErrFormat {
		t.Fatalf("Verify nil sig expected ErrFormat")
	}
	if err := Verify(sig.Bytes(), nil, msg, DomainNone()); err != ErrFormat {
		t.Fatalf("Verify nil pk expected ErrFormat")
	}

	// Verify with invalid signature header
	badSig := cloneBytes(sig.Bytes())
	badSig[0] = 0x99
	if err := Verify(badSig, kp.PublicKey(), msg, DomainNone()); err != ErrFormat {
		t.Fatalf("Verify bad sig header expected ErrFormat")
	}

	// Test (s *Signature) Verify
	if err := sig2.Verify(kp.PublicKey(), msg, DomainNone()); err != nil {
		t.Fatalf("sig2.Verify error: %v", err)
	}

	var nilSig *Signature
	if err := nilSig.Verify(kp.PublicKey(), msg, DomainNone()); err != ErrFormat {
		t.Fatalf("nilSig.Verify expected ErrFormat")
	}
	if nilSig.Bytes() != nil {
		t.Fatalf("nilSig.Bytes() expected nil")
	}
	if nilSig.Len() != 0 {
		t.Fatalf("nilSig.Len() expected 0")
	}

	// Test domainInputs error paths
	badDomain := Domain{prehash: true, alg: 99} // Unsupported hash
	_, err = kp.SignDeterministic(msg, []byte("seed"), badDomain)
	if err != ErrBadArgument {
		t.Fatalf("domainInputs with invalid alg expected ErrBadArgument, got %v", err)
	}
}
