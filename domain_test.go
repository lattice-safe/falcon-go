package falcon

import (
	"bytes"
	"testing"
)

func TestDomainValidation(t *testing.T) {
	if _, err := DomainContext(make([]byte, 256)); err != ErrBadArgument {
		t.Fatalf("DomainContext(256 bytes) error = %v, want ErrBadArgument", err)
	}
	if _, err := DomainContext(make([]byte, 255)); err != nil {
		t.Fatalf("DomainContext(255 bytes) error = %v", err)
	}
	if _, err := DomainPrehashed(0, nil); err != ErrBadArgument {
		t.Fatalf("DomainPrehashed(0) error = %v, want ErrBadArgument", err)
	}
	if _, err := DomainPrehashed(PreHashSHA256, make([]byte, 256)); err != ErrBadArgument {
		t.Fatalf("DomainPrehashed(oversized ctx) error = %v, want ErrBadArgument", err)
	}
	if _, err := DomainPrehashed(99, nil); err != ErrBadArgument {
		t.Fatalf("DomainPrehashed(invalid alg) error = %v, want ErrBadArgument", err)
	}

	invalidDomainCtx := Domain{context: make([]byte, 256)}
	if err := invalidDomainCtx.validate(); err != ErrBadArgument {
		t.Fatalf("validate oversized ctx error = %v, want ErrBadArgument", err)
	}

	invalidDomainAlg := Domain{prehash: true, alg: 99}
	if err := invalidDomainAlg.validate(); err != ErrBadArgument {
		t.Fatalf("validate invalid alg error = %v, want ErrBadArgument", err)
	}
	if got := invalidDomainAlg.messageForHash([]byte("test")); got != nil {
		t.Fatalf("messageForHash invalid alg = %v, want nil", got)
	}
}

func TestDomainCopiesContext(t *testing.T) {
	ctx := []byte("protocol-v1")
	d, err := DomainContext(ctx)
	if err != nil {
		t.Fatal(err)
	}
	ctx[0] = 'P'
	if bytes.Equal(d.context, ctx) {
		t.Fatal("domain context aliases caller buffer")
	}
}

func TestAllDomainPrehashAlgorithms(t *testing.T) {
	algs := []PreHashAlgorithm{
		PreHashSHA256,
		PreHashSHA384,
		PreHashSHA512,
		PreHashSHA512_256,
		PreHashSHA3_256,
		PreHashSHA3_384,
		PreHashSHA3_512,
	}
	for _, alg := range algs {
		d, err := DomainPrehashed(alg, []byte("ctx"))
		if err != nil {
			t.Fatalf("DomainPrehashed(%d) failed: %v", alg, err)
		}
		if err := d.validate(); err != nil {
			t.Fatalf("d.validate(%d) failed: %v", alg, err)
		}
		msg := []byte("test prehash data")
		hashed := d.messageForHash(msg)
		if len(hashed) == 0 {
			t.Fatalf("d.messageForHash(%d) returned empty", alg)
		}
	}
}

func TestDomainNoneMessageForHash(t *testing.T) {
	d := DomainNone()
	msg := []byte("hello")
	if !bytes.Equal(d.messageForHash(msg), msg) {
		t.Fatal("DomainNone messageForHash did not return original message")
	}
}
