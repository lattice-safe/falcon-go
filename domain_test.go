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

func TestDomainPrehash(t *testing.T) {
	d, err := DomainPrehashed(PreHashSHA256, nil)
	if err != nil {
		t.Fatal(err)
	}
	got := d.messageForHash([]byte("abc"))
	want := []byte{
		0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea,
		0x41, 0x41, 0x40, 0xde, 0x5d, 0xae, 0x22, 0x23,
		0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17, 0x7a, 0x9c,
		0xb4, 0x10, 0xff, 0x61, 0xf2, 0x00, 0x15, 0xad,
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("sha256 prehash mismatch: %x", got)
	}
}
