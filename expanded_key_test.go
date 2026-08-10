package falcon

import (
	"crypto/rand"
	"testing"
)

func TestExpandedKeyNilReceiverAndErrors(t *testing.T) {
	var nilKp *KeyPair
	if _, err := nilKp.Expand(); err != ErrBadArgument {
		t.Fatalf("nil KeyPair Expand error = %v, want ErrBadArgument", err)
	}

	invalidKp := &KeyPair{privateKey: []byte{0x00, 0x01}}
	if _, err := invalidKp.Expand(); err == nil {
		t.Fatal("invalid KeyPair Expand expected error")
	}

	var nilEk *ExpandedKey
	if _, err := nilEk.Sign([]byte("msg"), DomainNone()); err != ErrBadArgument {
		t.Fatalf("nil ExpandedKey Sign error = %v, want ErrBadArgument", err)
	}
	if _, err := nilEk.SignDeterministic([]byte("msg"), []byte("seed"), DomainNone()); err != ErrBadArgument {
		t.Fatalf("nil ExpandedKey SignDeterministic error = %v, want ErrBadArgument", err)
	}
	if got := nilEk.PublicKey(); got != nil {
		t.Fatalf("nil ExpandedKey PublicKey = %v, want nil", got)
	}
	if got := nilEk.LogN(); got != 0 {
		t.Fatalf("nil ExpandedKey LogN = %d, want 0", got)
	}

	uninitEk := &ExpandedKey{}
	if _, err := uninitEk.Sign([]byte("msg"), DomainNone()); err != ErrBadArgument {
		t.Fatalf("uninit ExpandedKey Sign error = %v, want ErrBadArgument", err)
	}
	if _, err := uninitEk.SignDeterministic([]byte("msg"), []byte("seed"), DomainNone()); err != ErrBadArgument {
		t.Fatalf("uninit ExpandedKey SignDeterministic error = %v, want ErrBadArgument", err)
	}
	if got := uninitEk.PublicKey(); got != nil {
		t.Fatalf("uninit ExpandedKey PublicKey = %v, want nil", got)
	}
	if got := uninitEk.LogN(); got != 0 {
		t.Fatalf("uninit ExpandedKey LogN = %d, want 0", got)
	}
}

func TestExpandedKeySignRandomAndLogN(t *testing.T) {
	kp, err := GenerateDeterministic([]byte("expanded-key-test-seed"), 9)
	if err != nil {
		t.Fatal(err)
	}
	ek, err := kp.Expand()
	if err != nil {
		t.Fatal(err)
	}
	if got := ek.LogN(); got != 9 {
		t.Fatalf("ek.LogN() = %d, want 9", got)
	}
	if len(ek.PublicKey()) != 897 {
		t.Fatalf("ek.PublicKey() len = %d, want 897", len(ek.PublicKey()))
	}
	sig, err := ek.Sign([]byte("random sign message"), DomainNone())
	if err != nil {
		t.Fatalf("ek.Sign failed: %v", err)
	}
	if err := Verify(sig.Bytes(), kp.PublicKey(), []byte("random sign message"), DomainNone()); err != nil {
		t.Fatalf("Verify random expanded sig failed: %v", err)
	}

	// Test Sign with broken rand
	oldReader := rand.Reader
	rand.Reader = errReader{}
	_, err = ek.Sign([]byte("msg"), DomainNone())
	if err != ErrRandom {
		t.Fatalf("ek.Sign broken rand expected ErrRandom, got %v", err)
	}
	rand.Reader = oldReader

	invalidDomain := Domain{context: make([]byte, 256)}
	if _, err := ek.SignDeterministic([]byte("msg"), []byte("seed"), invalidDomain); err != ErrBadArgument {
		t.Fatalf("ek.SignDeterministic with invalid domain error = %v, want ErrBadArgument", err)
	}
}
