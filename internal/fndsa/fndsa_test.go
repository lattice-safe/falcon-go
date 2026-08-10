package fndsa

import (
	"crypto"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"testing"
)

func TestMqOps(t *testing.T) {
	if mq_add(100, q-50) != 50 {
		t.Fatal("mq_add failed")
	}
	if mq_sub(50, 100) != q-50 {
		t.Fatal("mq_sub failed")
	}
	_ = mq_div(0, 100)
}

func TestKeyGenAndSignExport(t *testing.T) {
	// Test KeyGen with rand.Reader
	sk, pk, err := KeyGen(9, rand.Reader)
	if err != nil {
		t.Fatalf("KeyGen(9) failed: %v", err)
	}
	if len(sk) != SigningKeySize(9) || len(pk) != VerifyingKeySize(9) {
		t.Fatalf("KeyGen sizes incorrect: sk=%d, pk=%d", len(sk), len(pk))
	}

	// KeyGen invalid logn
	if _, _, err := KeyGen(1, rand.Reader); err == nil {
		t.Fatal("KeyGen(1) expected error")
	}
	if _, _, err := KeyGenDeterministic(1, make([]byte, 32)); err == nil {
		t.Fatal("KeyGenDeterministic(1) expected error")
	}

	// PrepareSigningKey
	prep, err := PrepareSigningKey(sk)
	if err != nil {
		t.Fatalf("PrepareSigningKey failed: %v", err)
	}
	if prep.LogN() != 9 {
		t.Fatalf("LogN() = %d, want 9", prep.LogN())
	}
	if len(prep.PublicKey()) != VerifyingKeySize(9) {
		t.Fatalf("PublicKey() len mismatch")
	}

	// SignCTDeterministic
	data := []byte("test message")
	seed := make([]byte, 40)
	sigCT, err := SignCTDeterministic(seed, sk, nil, crypto.SHA256, data)
	if err != nil {
		t.Fatalf("SignCTDeterministic failed: %v", err)
	}
	if !VerifyCT(pk, nil, crypto.SHA256, data, sigCT) {
		t.Fatal("VerifyCT failed on SignCTDeterministic signature")
	}

	// SignCTWithNonceSampler
	nonce := make([]byte, 40)
	samplerStream := make([]byte, 56*32)
	sigCT2, err := prep.SignCTWithNonceSampler(nonce, samplerStream, nil, crypto.SHA256, data)
	if err != nil {
		t.Fatalf("SignCTWithNonceSampler failed: %v", err)
	}
	if !VerifyCT(pk, nil, crypto.SHA256, data, sigCT2) {
		t.Fatal("VerifyCT failed on SignCTWithNonceSampler signature")
	}

	// SignPaddedDeterministic
	sigPadded, err := prep.SignPaddedDeterministic(seed, nil, crypto.SHA256, data)
	if err != nil {
		t.Fatalf("SignPaddedDeterministic failed: %v", err)
	}
	if !Verify(pk, nil, crypto.SHA256, data, sigPadded) {
		t.Fatal("Verify failed on SignPaddedDeterministic signature")
	}

	// Sign (high level padded sign)
	sigPadded2, err := Sign(rand.Reader, sk, nil, crypto.SHA256, data)
	if err != nil {
		t.Fatalf("Sign failed: %v", err)
	}
	if !Verify(pk, nil, crypto.SHA256, data, sigPadded2) {
		t.Fatal("Verify failed on Sign signature")
	}
}

func TestVerifyCTErrors(t *testing.T) {
	sk, pk, _ := KeyGenDeterministic(9, make([]byte, 48))
	prep, _ := PrepareSigningKey(sk)
	data := []byte("verify ct data")
	sigCT, _ := prep.SignCTDeterministic(make([]byte, 40), nil, crypto.SHA256, data)

	// nil/empty parameters
	if VerifyCT(nil, nil, 0, data, sigCT) {
		t.Fatal("VerifyCT nil vkey expected false")
	}
	if VerifyCT(pk, nil, 0, data, nil) {
		t.Fatal("VerifyCT nil sig expected false")
	}

	// Header mismatches
	badVkey := cloneFndsa(pk)
	badVkey[0] = 0x19 // non-zero header
	if VerifyCT(badVkey, nil, 0, data, sigCT) {
		t.Fatal("VerifyCT bad vkey header expected false")
	}

	badSig := cloneFndsa(sigCT)
	badSig[0] = 0x39 // 0x30 instead of 0x50
	if VerifyCT(pk, nil, 0, data, badSig) {
		t.Fatal("VerifyCT bad sig header expected false")
	}

	// Degree mismatch
	badLognVkey := cloneFndsa(pk)
	badLognVkey[0] = 0x02 // logn = 2 (not 9 or 10)
	if VerifyCT(badLognVkey, nil, 0, data, sigCT) {
		t.Fatal("VerifyCT logn=2 expected false")
	}

	// Short vkey / sig
	if VerifyCT(pk[:10], nil, 0, data, sigCT) {
		t.Fatal("VerifyCT short vkey expected false")
	}
	if VerifyCT(pk, nil, 0, data, sigCT[:10]) {
		t.Fatal("VerifyCT short sig expected false")
	}

	// Corrupt modq_decode / trim_i16_decode in VerifyCT
	corruptVkey := cloneFndsa(pk)
	corruptVkey[1] = 0xFF
	corruptVkey[2] = 0xFF
	if VerifyCT(corruptVkey, nil, 0, data, sigCT) {
		t.Fatal("VerifyCT corrupt vkey expected false")
	}

	corruptSig := cloneFndsa(sigCT)
	for i := 41; i < len(corruptSig); i++ {
		corruptSig[i] = 0xFF
	}
	if VerifyCT(pk, nil, 0, data, corruptSig) {
		t.Fatal("VerifyCT corrupt sig expected false")
	}
}

func TestPreparedKeyNilReceivers(t *testing.T) {
	var nilPrep *PreparedKey
	if _, err := nilPrep.SignCTDeterministic(make([]byte, 40), nil, 0, []byte("msg")); err == nil {
		t.Fatal("nilPrepared SignCTDeterministic expected error")
	}
	if _, err := nilPrep.SignCTWithNonceSampler(make([]byte, 40), make([]byte, 100), nil, 0, []byte("msg")); err == nil {
		t.Fatal("nilPrepared SignCTWithNonceSampler expected error")
	}
	if _, err := nilPrep.SignPaddedDeterministic(make([]byte, 40), nil, 0, []byte("msg")); err == nil {
		t.Fatal("nilPrepared SignPaddedDeterministic expected error")
	}
	if _, err := nilPrep.SignPaddedWithNonceSampler(make([]byte, 40), make([]byte, 100), nil, 0, []byte("msg")); err == nil {
		t.Fatal("nilPrepared SignPaddedWithNonceSampler expected error")
	}
	if got := nilPrep.PublicKey(); got != nil {
		t.Fatalf("nilPrepared PublicKey = %v, want nil", got)
	}
	if got := nilPrep.LogN(); got != 0 {
		t.Fatalf("nilPrepared LogN = %d, want 0", got)
	}
}

func TestVerifyWeak(t *testing.T) {
	sk, pk, err := KeyGenDeterministic(2, make([]byte, 48))
	if err != nil {
		t.Fatalf("KeyGen failed: %v", err)
	}
	f, g, F, G, logn, err := decodeSigningKey(2, 8, sk)
	if err != nil {
		t.Fatalf("decodeSigningKey failed: %v", err)
	}
	vrfyKey, _ := makePublicFromDecoded(logn, f, g, F)
	pre := &PreparedKey{
		f:         f,
		g:         g,
		F:         F,
		G:         G,
		logn:      logn,
		verifying: vrfyKey,
		hashedVK:  hash_verifying_key(vrfyKey),
	}
	nonce := make([]byte, 40)
	sig, err := pre.SignPaddedWithNonceSampler(nonce, make([]byte, 48*1024), nil, crypto.Hash(0), []byte("test"))
	if err != nil {
		t.Fatalf("Sign failed: %v", err)
	}

	if !VerifyWeak(pk, nil, crypto.Hash(0), []byte("test"), sig) {
		t.Fatal("VerifyWeak failed")
	}
	if VerifyWeak(make([]byte, 10), nil, crypto.Hash(0), []byte("test"), sig) {
		t.Fatal("VerifyWeak succeeded on bad pk")
	}
	badSig := make([]byte, len(sig))
	copy(badSig, sig)
	badSig[0] = 0x52
	if VerifyWeak(pk, nil, crypto.Hash(0), []byte("test"), badSig) {
		t.Fatal("VerifyWeak succeeded on CT format")
	}
	if VerifyWeak(pk, nil, crypto.Hash(0), []byte("test"), make([]byte, 10)) {
		t.Fatal("VerifyWeak succeeded on short sig")
	}

	// SignWeak test
	sigWeak, err := SignWeak(rand.Reader, sk, nil, 0, []byte("weak msg"))
	if err != nil {
		t.Fatalf("SignWeak failed: %v", err)
	}
	if !VerifyWeak(pk, nil, 0, []byte("weak msg"), sigWeak) {
		t.Fatal("VerifyWeak failed on SignWeak signature")
	}
}

func TestNbitsFG(t *testing.T) {
	degrees := []struct {
		logn uint
		want int
	}{
		{2, 8}, {3, 8}, {4, 8}, {5, 8},
		{6, 7}, {7, 7},
		{8, 6}, {9, 6},
		{1, 5}, {10, 5},
	}
	for _, d := range degrees {
		if got := nbits_fg(d.logn); got != d.want {
			t.Fatalf("nbits_fg(%d) = %d, want %d", d.logn, got, d.want)
		}
	}
}

func TestHashToPointAllOIDsAndErrors(t *testing.T) {
	logn := uint(9)
	n := 1 << logn
	c := make([]uint16, n)
	nonce := make([]byte, 40)
	hvk := make([]byte, 64)
	data := []byte("hash data test")

	hashes := []crypto.Hash{
		0,
		crypto.SHA256,
		crypto.SHA384,
		crypto.SHA512,
		crypto.SHA512_256,
		crypto.SHA3_256,
		crypto.SHA3_384,
		crypto.SHA3_512,
		crypto.Hash(0xFFFFFFFF),
	}

	for _, h := range hashes {
		if err := hash_to_point(logn, nonce, hvk, DomainContext("ctx"), h, data, c); err != nil {
			t.Fatalf("hash_to_point(%v) failed: %v", h, err)
		}
	}

	// Invalid OID
	if err := hash_to_point(logn, nonce, hvk, DomainContext("ctx"), crypto.MD5, data, c); err == nil {
		t.Fatal("hash_to_point expected error on unsupported crypto.MD5")
	}

	// Oversized context
	if err := hash_to_point(logn, nonce, hvk, DomainContext(make([]byte, 256)), crypto.SHA256, data, c); err == nil {
		t.Fatal("hash_to_point expected error on oversized context")
	}
}

func TestShake256PrngEdgeCases(t *testing.T) {
	seed := sha256.Sum256([]byte("shake256prng-test"))
	rng := newSHAKE256prng(seed[:])

	// Read exact 136 bytes to hit ptr == len(buf) in next_u8
	for i := 0; i < 136; i++ {
		rng.next_u8()
	}
	_ = rng.next_u8() // triggers buf refill

	// Force ptr near end for next_u16
	rng.ptr = len(rng.buf) - 1
	_ = rng.next_u16()

	// Force ptr near end for next_u64
	rng.ptr = len(rng.buf) - 5
	_ = rng.next_u64()

	rng.ptr = 10
	_ = rng.next_u64()
}

func TestCodecExtTrimI16AndSigCT(t *testing.T) {
	for _, logn := range []uint{9, 10} {
		if signatureSizeCT(logn) <= 0 {
			t.Fatalf("signatureSizeCT(%d) invalid", logn)
		}
	}

	n := 512
	x := make([]int16, n)
	x[0] = 10
	x[1] = -10
	bits := 12
	outLen := (n*bits + 7) >> 3
	buf := make([]byte, outLen)

	if !trim_i16_encode(9, x, bits, buf) {
		t.Fatal("trim_i16_encode failed")
	}

	decoded := make([]int16, n)
	if _, err := trim_i16_decode(9, buf, decoded, bits); err != nil {
		t.Fatalf("trim_i16_decode failed: %v", err)
	}
	if decoded[0] != 10 || decoded[1] != -10 {
		t.Fatalf("trim_i16 decode mismatch: %v, %v", decoded[0], decoded[1])
	}

	// trim_i16_encode out of bounds
	xBad := make([]int16, n)
	xBad[0] = 4000 // exceeds 12 bits max
	if trim_i16_encode(9, xBad, bits, buf) {
		t.Fatal("trim_i16_encode should fail on out-of-bounds value")
	}

	// trim_i16_decode invalid length
	if _, err := trim_i16_decode(9, buf[:10], decoded, bits); err == nil {
		t.Fatal("trim_i16_decode expected error on short input")
	}

	// trim_i16_decode -2048 (mask2 value)
	badBuf := make([]byte, outLen)
	badBuf[0] = 0x80
	if _, err := trim_i16_decode(9, badBuf, decoded, bits); err == nil {
		t.Fatal("trim_i16_decode expected error on mask2 value")
	}

	// trim_i16_decode trailing non-zero padding
	validBuf := make([]byte, 3) // logn=1, n=2, bits=11
	x2 := make([]int16, 2)
	trim_i16_encode(1, x2, 11, validBuf)
	validBuf[2] |= 0x01
	if _, err := trim_i16_decode(1, validBuf, make([]int16, 2), 11); err == nil {
		t.Fatal("trim_i16_decode expected error on non-zero padding")
	}
}

func TestDecodeSigningKeyErrors(t *testing.T) {
	sk, _, _ := KeyGenDeterministic(9, make([]byte, 48))

	// empty skey
	if _, _, _, _, _, err := decodeSigningKey(9, 10, nil); err == nil {
		t.Fatal("decodeSigningKey expected error on nil skey")
	}

	// wrong header
	badSk := cloneFndsa(sk)
	badSk[0] = 0x39
	if _, _, _, _, _, err := decodeSigningKey(9, 10, badSk); err == nil {
		t.Fatal("decodeSigningKey expected error on wrong header")
	}

	// wrong logn range
	if _, _, _, _, _, err := decodeSigningKey(10, 10, sk); err == nil {
		t.Fatal("decodeSigningKey expected error on logn out of range")
	}

	// wrong size
	if _, _, _, _, _, err := decodeSigningKey(9, 10, sk[:100]); err == nil {
		t.Fatal("decodeSigningKey expected error on wrong size")
	}

	// corrupt f
	corruptF := cloneFndsa(sk)
	for i := 1; i < 200; i++ {
		corruptF[i] = 0xFF
	}
	if _, _, _, _, _, err := decodeSigningKey(9, 10, corruptF); err == nil {
		t.Fatal("decodeSigningKey expected error on corrupt f")
	}
}

func TestMakePublicAndExportHelpers(t *testing.T) {
	sk, pk, _ := KeyGenDeterministic(9, make([]byte, 48))
	pub, err := MakePublic(sk)
	if err != nil {
		t.Fatalf("MakePublic failed: %v", err)
	}
	if string(pub) != string(pk) {
		t.Fatal("MakePublic returned mismatching public key")
	}

	// PrepareSigningKey error
	if _, err := PrepareSigningKey(make([]byte, 10)); err == nil {
		t.Fatal("PrepareSigningKey expected error on short sk")
	}

	// SignCTDeterministic error on bad key
	if _, err := SignCTDeterministic(make([]byte, 40), make([]byte, 10), nil, 0, []byte("msg")); err == nil {
		t.Fatal("SignCTDeterministic expected error on bad key")
	}

	// Sign with broken reader
	if _, err := Sign(errReaderFndsa{}, sk, nil, 0, []byte("msg")); err == nil {
		t.Fatal("Sign expected error on broken reader")
	}
	if _, err := Sign(nil, make([]byte, 10), nil, 0, []byte("msg")); err == nil {
		t.Fatal("Sign expected error on bad sk")
	}
}

type errReaderFndsa struct{}

func (errReaderFndsa) Read(p []byte) (n int, err error) {
	return 0, errors.New("reader error")
}

func cloneFndsa(b []byte) []byte {
	out := make([]byte, len(b))
	copy(out, b)
	return out
}
