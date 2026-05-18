package falcon

import (
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"
)

func TestGenerateSignVerify512(t *testing.T) {
	kp, err := GenerateDeterministic([]byte("falcon-go-test-key-seed-512"), 9)
	if err != nil {
		t.Fatal(err)
	}
	if got := len(kp.PrivateKey()); got != 1281 {
		t.Fatalf("private key len = %d, want 1281", got)
	}
	if got := len(kp.PublicKey()); got != 897 {
		t.Fatalf("public key len = %d, want 897", got)
	}
	sig, err := kp.SignDeterministic([]byte("hello fn-dsa"), []byte("falcon-go-sign-seed"), DomainNone())
	if err != nil {
		t.Fatal(err)
	}
	if got := sig.Len(); got != 809 {
		t.Fatalf("signature len = %d, want 809", got)
	}
	if err := Verify(sig.Bytes(), kp.PublicKey(), []byte("hello fn-dsa"), DomainNone()); err != nil {
		t.Fatalf("verify failed: %v", err)
	}
	if err := Verify(sig.Bytes(), kp.PublicKey(), []byte("wrong"), DomainNone()); err != ErrBadSignature {
		t.Fatalf("wrong message error = %v, want ErrBadSignature", err)
	}
}

func TestPublicSizeHelpers(t *testing.T) {
	tests := []struct {
		logn          uint
		sk, pk, sigCT int
	}{
		{9, 1281, 897, 809},
		{10, 2305, 1793, 1577},
	}
	for _, tt := range tests {
		if got, err := PrivateKeySize(tt.logn); err != nil || got != tt.sk {
			t.Fatalf("PrivateKeySize(%d) = %d, %v; want %d, nil", tt.logn, got, err, tt.sk)
		}
		if got, err := PublicKeySize(tt.logn); err != nil || got != tt.pk {
			t.Fatalf("PublicKeySize(%d) = %d, %v; want %d, nil", tt.logn, got, err, tt.pk)
		}
		if got, err := SignatureSize(tt.logn); err != nil || got != tt.sigCT {
			t.Fatalf("SignatureSize(%d) = %d, %v; want %d, nil", tt.logn, got, err, tt.sigCT)
		}
	}
	if _, err := PrivateKeySize(8); err != ErrBadArgument {
		t.Fatalf("PrivateKeySize(8) error = %v, want ErrBadArgument", err)
	}
}

func TestGenerateSignVerify1024(t *testing.T) {
	kp, err := GenerateDeterministic([]byte("falcon-go-test-key-seed-1024"), 10)
	if err != nil {
		t.Fatal(err)
	}
	sig, err := kp.SignDeterministic([]byte("hello fn-dsa-1024"), []byte("falcon-go-sign-seed"), DomainNone())
	if err != nil {
		t.Fatal(err)
	}
	if got := len(kp.PrivateKey()); got != 2305 {
		t.Fatalf("private key len = %d, want 2305", got)
	}
	if got := len(kp.PublicKey()); got != 1793 {
		t.Fatalf("public key len = %d, want 1793", got)
	}
	if got := sig.Len(); got != 1577 {
		t.Fatalf("signature len = %d, want 1577", got)
	}
	if err := Verify(sig.Bytes(), kp.PublicKey(), []byte("hello fn-dsa-1024"), DomainNone()); err != nil {
		t.Fatalf("verify failed: %v", err)
	}
}

func TestDeterministicSignatureReproducible(t *testing.T) {
	kp, err := GenerateDeterministic([]byte("falcon-go-deterministic-key"), 9)
	if err != nil {
		t.Fatal(err)
	}
	domain, err := DomainContext([]byte("ctx-v1"))
	if err != nil {
		t.Fatal(err)
	}
	a, err := kp.SignDeterministic([]byte("message"), []byte("same-sign-seed"), domain)
	if err != nil {
		t.Fatal(err)
	}
	b, err := kp.SignDeterministic([]byte("message"), []byte("same-sign-seed"), domain)
	if err != nil {
		t.Fatal(err)
	}
	if string(a.Bytes()) != string(b.Bytes()) {
		t.Fatal("deterministic signatures differ")
	}
}

func TestImportPrivateAndExpandedKey(t *testing.T) {
	kp, err := GenerateDeterministic([]byte("falcon-go-import-key"), 9)
	if err != nil {
		t.Fatal(err)
	}
	restored, err := FromPrivateKey(kp.PrivateKey())
	if err != nil {
		t.Fatal(err)
	}
	if string(restored.PublicKey()) != string(kp.PublicKey()) {
		t.Fatal("public key recomputation mismatch")
	}
	ek, err := restored.Expand()
	if err != nil {
		t.Fatal(err)
	}
	sig, err := ek.SignDeterministic([]byte("expanded"), []byte("expanded-seed"), DomainNone())
	if err != nil {
		t.Fatal(err)
	}
	sig2, err := restored.SignDeterministic([]byte("expanded"), []byte("expanded-seed"), DomainNone())
	if err != nil {
		t.Fatal(err)
	}
	if string(sig.Bytes()) != string(sig2.Bytes()) {
		t.Fatal("expanded deterministic signature differs from key-pair deterministic signature")
	}
	if err := Verify(sig.Bytes(), ek.PublicKey(), []byte("expanded"), DomainNone()); err != nil {
		t.Fatalf("verify expanded signature failed: %v", err)
	}
}

func TestPrehashedDomains(t *testing.T) {
	kp, err := GenerateDeterministic([]byte("falcon-go-prehash-key"), 9)
	if err != nil {
		t.Fatal(err)
	}
	d256, err := DomainPrehashed(PreHashSHA256, nil)
	if err != nil {
		t.Fatal(err)
	}
	d512, err := DomainPrehashed(PreHashSHA512, []byte("ctx"))
	if err != nil {
		t.Fatal(err)
	}
	msg := []byte("prehash me")
	s256, err := kp.SignDeterministic(msg, []byte("seed-256"), d256)
	if err != nil {
		t.Fatal(err)
	}
	if err := Verify(s256.Bytes(), kp.PublicKey(), msg, d256); err != nil {
		t.Fatalf("sha256 verify failed: %v", err)
	}
	s512, err := kp.SignDeterministic(msg, []byte("seed-512"), d512)
	if err != nil {
		t.Fatal(err)
	}
	if err := Verify(s512.Bytes(), kp.PublicKey(), msg, d512); err != nil {
		t.Fatalf("sha512 verify failed: %v", err)
	}
	if err := Verify(s512.Bytes(), kp.PublicKey(), msg, d256); err != ErrBadSignature {
		t.Fatalf("cross-domain error = %v, want ErrBadSignature", err)
	}
}

func TestRustFIPS206FixturesVerify(t *testing.T) {
	msg := []byte("FIPS 206 FN-DSA Known Answer Test")
	tests := []struct {
		name   string
		domain Domain
	}{
		{"FN-DSA-512__DomainSeparation_None", DomainNone()},
		{"FN-DSA-1024__DomainSeparation_None", DomainNone()},
	}
	ctx, err := DomainContext([]byte("fips206-ctx-v1"))
	if err != nil {
		t.Fatal(err)
	}
	tests = append(tests, struct {
		name   string
		domain Domain
	}{"FN-DSA-512__DomainSeparation_Context_b_fips206-ctx-v1", ctx})

	d256, err := DomainPrehashed(PreHashSHA256, nil)
	if err != nil {
		t.Fatal(err)
	}
	tests = append(tests, struct {
		name   string
		domain Domain
	}{"FN-DSA-512__Prehashed_SHA-256_no_ctx", d256})

	d512ctx, err := DomainPrehashed(PreHashSHA512, []byte("fips206-ctx-v1"))
	if err != nil {
		t.Fatal(err)
	}
	tests = append(tests, struct {
		name   string
		domain Domain
	}{
		"FN-DSA-512__Prehashed_SHA-512_ctx_b_fips206-ctx-v1", d512ctx,
	}, struct {
		name   string
		domain Domain
	}{
		"FN-DSA-1024__Prehashed_SHA-512_ctx_b_fips206-ctx-v1", d512ctx,
	})

	for _, tt := range tests {
		pk := readHexFixture(t, tt.name+"_pk.hex")
		sig := readHexFixture(t, tt.name+"_sig.hex")
		if err := Verify(sig, pk, msg, tt.domain); err != nil {
			t.Fatalf("%s did not verify: %v", tt.name, err)
		}
		if err := Verify(sig, pk, []byte("WRONG_MSG"), tt.domain); err != ErrBadSignature {
			t.Fatalf("%s wrong message error = %v, want ErrBadSignature", tt.name, err)
		}
	}
}

func TestRustFIPS206DeterministicBytes(t *testing.T) {
	msg := []byte("FIPS 206 FN-DSA Known Answer Test")
	signSeed := []byte("fips206-kat-sign-seed")
	tests := []struct {
		name    string
		keySeed []byte
		logn    uint
		domain  Domain
	}{
		{"FN-DSA-512__DomainSeparation_None", []byte("fips206-kat-key-seed-512"), 9, DomainNone()},
		{"FN-DSA-1024__DomainSeparation_None", []byte("fips206-kat-key-seed-1024"), 10, DomainNone()},
	}
	ctx, err := DomainContext([]byte("fips206-ctx-v1"))
	if err != nil {
		t.Fatal(err)
	}
	tests = append(tests, struct {
		name    string
		keySeed []byte
		logn    uint
		domain  Domain
	}{"FN-DSA-512__DomainSeparation_Context_b_fips206-ctx-v1", []byte("fips206-kat-key-seed-512"), 9, ctx})

	d256, err := DomainPrehashed(PreHashSHA256, nil)
	if err != nil {
		t.Fatal(err)
	}
	tests = append(tests, struct {
		name    string
		keySeed []byte
		logn    uint
		domain  Domain
	}{"FN-DSA-512__Prehashed_SHA-256_no_ctx", []byte("fips206-kat-key-seed-512"), 9, d256})

	d512ctx, err := DomainPrehashed(PreHashSHA512, []byte("fips206-ctx-v1"))
	if err != nil {
		t.Fatal(err)
	}
	tests = append(tests, struct {
		name    string
		keySeed []byte
		logn    uint
		domain  Domain
	}{
		"FN-DSA-512__Prehashed_SHA-512_ctx_b_fips206-ctx-v1", []byte("fips206-kat-key-seed-512"), 9, d512ctx,
	}, struct {
		name    string
		keySeed []byte
		logn    uint
		domain  Domain
	}{
		"FN-DSA-1024__Prehashed_SHA-512_ctx_b_fips206-ctx-v1", []byte("fips206-kat-key-seed-1024"), 10, d512ctx,
	})
	for _, tt := range tests {
		kp, err := GenerateDeterministic(tt.keySeed, tt.logn)
		if err != nil {
			t.Fatal(err)
		}
		expectedPK := readHexFixture(t, tt.name+"_pk.hex")
		if got := kp.PublicKey(); string(got) != string(expectedPK) {
			t.Fatalf("%s public key mismatch\n got: %x\nwant: %x", tt.name, got[:16], expectedPK[:16])
		}
		sig, err := kp.SignDeterministic(msg, signSeed, tt.domain)
		if err != nil {
			t.Fatal(err)
		}
		expectedSig := readHexFixture(t, tt.name+"_sig.hex")
		if got := sig.Bytes(); string(got) != string(expectedSig) {
			t.Fatalf("%s signature mismatch\n got: %x\nwant: %x", tt.name, got[:16], expectedSig[:16])
		}
	}
}

func readHexFixture(t *testing.T, name string) []byte {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("testdata", "fips206", name))
	if err != nil {
		t.Fatal(err)
	}
	out, err := hex.DecodeString(string(bytesTrimSpace(data)))
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func bytesTrimSpace(b []byte) []byte {
	for len(b) > 0 && (b[0] == ' ' || b[0] == '\n' || b[0] == '\r' || b[0] == '\t') {
		b = b[1:]
	}
	for len(b) > 0 {
		c := b[len(b)-1]
		if c != ' ' && c != '\n' && c != '\r' && c != '\t' {
			break
		}
		b = b[:len(b)-1]
	}
	return b
}
