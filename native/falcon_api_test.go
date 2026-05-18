package native

import (
	"bytes"
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"
)

func TestFalconNativeKeygenMakePublicAndLogN(t *testing.T) {
	var rng Shake256Context
	Shake256InitPRNGFromSeed(&rng, []byte("fips206-kat-key-seed-512"))

	sk := make([]byte, PrivKeySize(9))
	pk := make([]byte, PubKeySize(9))
	tmp := make([]byte, TmpSizeKeygen(9))
	if rc := FalconKeygenMake(&rng, 9, sk, pk, tmp); rc != 0 {
		t.Fatalf("FalconKeygenMake rc = %d", rc)
	}
	expectedPK := readNativeHexFixture(t, "FN-DSA-512__DomainSeparation_None_pk.hex")
	if !bytes.Equal(pk, expectedPK) {
		t.Fatalf("native keygen pk prefix = %x, want %x", pk[:16], expectedPK[:16])
	}
	if got := FalconGetLogN(sk); got != 9 {
		t.Fatalf("FalconGetLogN(sk) = %d, want 9", got)
	}
	if got := FalconGetLogN(pk); got != 9 {
		t.Fatalf("FalconGetLogN(pk) = %d, want 9", got)
	}

	recomputed := make([]byte, PubKeySize(9))
	if rc := FalconMakePublic(recomputed, sk, make([]byte, TmpSizeMakePub(9))); rc != 0 {
		t.Fatalf("FalconMakePublic rc = %d", rc)
	}
	if !bytes.Equal(recomputed, pk) {
		t.Fatal("recomputed public key mismatch")
	}
}

func TestFalconNativeSignVerifyCT(t *testing.T) {
	var kg Shake256Context
	Shake256InitPRNGFromSeed(&kg, []byte("native-sign-key-seed"))
	sk := make([]byte, PrivKeySize(9))
	pk := make([]byte, PubKeySize(9))
	if rc := FalconKeygenMake(&kg, 9, sk, pk, make([]byte, TmpSizeKeygen(9))); rc != 0 {
		t.Fatalf("FalconKeygenMake rc = %d", rc)
	}

	msg := []byte("native low-level message")
	var rng Shake256Context
	Shake256InitPRNGFromSeed(&rng, []byte("native-sign-seed"))
	sig := make([]byte, SigCTSize(9))
	sigLen := len(sig)
	if rc := FalconSignDyn(&rng, sig, &sigLen, SigCT, sk, msg, make([]byte, TmpSizeSignDyn(9))); rc != 0 {
		t.Fatalf("FalconSignDyn rc = %d", rc)
	}
	if sigLen != SigCTSize(9) {
		t.Fatalf("sigLen = %d, want %d", sigLen, SigCTSize(9))
	}
	if rc := FalconVerify(sig[:sigLen], SigCT, pk, msg, make([]byte, TmpSizeVerify(9))); rc != 0 {
		t.Fatalf("FalconVerify rc = %d", rc)
	}
	if rc := FalconVerify(sig[:sigLen], SigCT, pk, []byte("wrong"), make([]byte, TmpSizeVerify(9))); rc != ErrBadSig {
		t.Fatalf("wrong-message verify rc = %d, want %d", rc, ErrBadSig)
	}
}

func TestFalconNativeStreamedSignVerifyCT(t *testing.T) {
	var kg Shake256Context
	Shake256InitPRNGFromSeed(&kg, []byte("native-stream-key-seed"))
	sk := make([]byte, PrivKeySize(9))
	pk := make([]byte, PubKeySize(9))
	if rc := FalconKeygenMake(&kg, 9, sk, pk, make([]byte, TmpSizeKeygen(9))); rc != 0 {
		t.Fatalf("FalconKeygenMake rc = %d", rc)
	}

	var rng Shake256Context
	Shake256InitPRNGFromSeed(&rng, []byte("native-stream-sign-seed"))
	var nonce [40]byte
	var hd Shake256Context
	if rc := FalconSignStart(&rng, nonce[:], &hd); rc != 0 {
		t.Fatalf("FalconSignStart rc = %d", rc)
	}
	Shake256Inject(&hd, []byte("part one "))
	Shake256Inject(&hd, []byte("part two"))
	sig := make([]byte, SigCTSize(9))
	sigLen := len(sig)
	if rc := FalconSignDynFinish(&rng, sig, &sigLen, SigCT, sk, &hd, nonce[:], make([]byte, TmpSizeSignDyn(9))); rc != 0 {
		t.Fatalf("FalconSignDynFinish rc = %d", rc)
	}

	var vh Shake256Context
	if rc := FalconVerifyStart(&vh, sig[:sigLen]); rc != 0 {
		t.Fatalf("FalconVerifyStart rc = %d", rc)
	}
	Shake256Inject(&vh, []byte("part one "))
	Shake256Inject(&vh, []byte("part two"))
	if rc := FalconVerifyFinish(sig[:sigLen], SigCT, pk, &vh, make([]byte, TmpSizeVerify(9))); rc != 0 {
		t.Fatalf("FalconVerifyFinish rc = %d", rc)
	}
}

func TestFalconNativeSignVerifyPaddedAndCompressed(t *testing.T) {
	var kg Shake256Context
	Shake256InitPRNGFromSeed(&kg, []byte("native-format-key-seed"))
	sk := make([]byte, PrivKeySize(9))
	pk := make([]byte, PubKeySize(9))
	if rc := FalconKeygenMake(&kg, 9, sk, pk, make([]byte, TmpSizeKeygen(9))); rc != 0 {
		t.Fatalf("FalconKeygenMake rc = %d", rc)
	}

	for _, sigType := range []int{SigPadded, SigCompressed} {
		var rng Shake256Context
		Shake256InitPRNGFromSeed(&rng, []byte{byte(sigType), 's', 'e', 'e', 'd'})
		sig := make([]byte, signatureBufferSize(9, sigType))
		sigLen := len(sig)
		msg := []byte("format message")
		if rc := FalconSignDyn(&rng, sig, &sigLen, sigType, sk, msg, make([]byte, TmpSizeSignDyn(9))); rc != 0 {
			t.Fatalf("FalconSignDyn type %d rc = %d", sigType, rc)
		}
		if sigType == SigCompressed && sigLen >= SigPaddedSize(9) {
			t.Fatalf("compressed sigLen = %d, expected less than padded %d", sigLen, SigPaddedSize(9))
		}
		if rc := FalconVerify(sig[:sigLen], sigType, pk, msg, make([]byte, TmpSizeVerify(9))); rc != 0 {
			t.Fatalf("FalconVerify type %d rc = %d", sigType, rc)
		}
	}
}

func readNativeHexFixture(t *testing.T, name string) []byte {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("..", "testdata", "fips206", name))
	if err != nil {
		t.Fatal(err)
	}
	out, err := hex.DecodeString(string(bytes.TrimSpace(data)))
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func TestFalconNativeErrors(t *testing.T) {
	// FalconGetLogN errors
	if got := FalconGetLogN(nil); got != ErrFormat {
		t.Fatalf("FalconGetLogN(nil) = %d, want ErrFormat", got)
	}
	if got := FalconGetLogN([]byte{0x0b}); got != ErrFormat { // logn 11 is invalid
		t.Fatalf("FalconGetLogN(11) = %d, want ErrFormat", got)
	}

	var rng Shake256Context
	Shake256Init(&rng)

	// FalconKeygenMake errors
	if rc := FalconKeygenMake(nil, 9, nil, nil, nil); rc != ErrBadArg {
		t.Fatalf("FalconKeygenMake nil rng rc = %d", rc)
	}
	if rc := FalconKeygenMake(&rng, 1, nil, nil, nil); rc != ErrBadArg {
		t.Fatalf("FalconKeygenMake bad logn rc = %d", rc)
	}
	if rc := FalconKeygenMake(&rng, 9, make([]byte, 10), nil, nil); rc != ErrSize {
		t.Fatalf("FalconKeygenMake short sk rc = %d", rc)
	}

	// Generate a valid sk for further testing
	sk := make([]byte, PrivKeySize(9))
	pk := make([]byte, PubKeySize(9))
	FalconKeygenMake(&rng, 9, sk, pk, nil)

	// FalconMakePublic errors
	badSk := make([]byte, PrivKeySize(9))
	if rc := FalconMakePublic(pk, badSk, nil); rc != ErrFormat {
		t.Fatalf("FalconMakePublic bad sk rc = %d", rc)
	}
	if rc := FalconMakePublic(make([]byte, 10), sk, nil); rc != ErrSize {
		t.Fatalf("FalconMakePublic short pk rc = %d", rc)
	}
	badSk2 := cloneBytesNative(sk)
	badSk2[10] ^= 0xff
	if rc := FalconMakePublic(pk, badSk2, nil); rc != ErrFormat {
		t.Fatalf("FalconMakePublic corrupted sk rc = %d", rc)
	}

	// FalconSignStart errors
	var hd Shake256Context
	if rc := FalconSignStart(nil, make([]byte, 40), &hd); rc != ErrBadArg {
		t.Fatalf("FalconSignStart nil rng rc = %d", rc)
	}

	// FalconSignDynFinish errors
	sig := make([]byte, SigCTSize(9))
	sigLen := len(sig)
	if rc := FalconSignDynFinish(nil, sig, &sigLen, SigCT, sk, &hd, make([]byte, 40), nil); rc != ErrBadArg {
		t.Fatalf("FalconSignDynFinish nil rng rc = %d", rc)
	}
	if rc := FalconSignDynFinish(&rng, sig, &sigLen, SigCT, badSk, &hd, make([]byte, 40), nil); rc != ErrFormat {
		t.Fatalf("FalconSignDynFinish bad sk rc = %d", rc)
	}
	if rc := FalconSignDynFinish(&rng, sig, &sigLen, 99, sk, &hd, make([]byte, 40), nil); rc != ErrBadArg {
		t.Fatalf("FalconSignDynFinish bad sigType rc = %d", rc)
	}
	shortSigLen := 10
	if rc := FalconSignDynFinish(&rng, sig, &shortSigLen, SigCT, sk, &hd, make([]byte, 40), nil); rc != ErrSize {
		t.Fatalf("FalconSignDynFinish short sigLen rc = %d", rc)
	}

	// FalconVerifyStart errors
	if rc := FalconVerifyStart(nil, sig); rc != ErrFormat {
		t.Fatalf("FalconVerifyStart nil hd rc = %d", rc)
	}
	if rc := FalconVerifyStart(&hd, sig[:10]); rc != ErrFormat {
		t.Fatalf("FalconVerifyStart short sig rc = %d", rc)
	}

	// Generate valid sig
	var nonce [40]byte
	FalconSignStart(&rng, nonce[:], &hd)
	sigLen = len(sig)
	if rc := FalconSignDynFinish(&rng, sig, &sigLen, SigCT, sk, &hd, nonce[:], nil); rc != 0 {
		t.Fatalf("FalconSignDynFinish failed rc = %d", rc)
	}

	// FalconVerifyFinish errors
	if rc := FalconVerifyFinish(sig, SigCT, pk, nil, nil); rc != ErrFormat {
		t.Fatalf("FalconVerifyFinish nil hd rc = %d", rc)
	}
	if rc := FalconVerifyFinish(sig, SigCT, badSk, &hd, nil); rc != ErrFormat {
		t.Fatalf("FalconVerifyFinish bad pk rc = %d", rc)
	}
	badSigLogn := cloneBytesNative(sig)
	badSigLogn[0] = 0x58
	if rc := FalconVerifyFinish(badSigLogn, SigCT, pk, &hd, nil); rc != ErrBadSig {
		t.Fatalf("FalconVerifyFinish bad sig logn rc = %d", rc)
	}
	var emptyHd Shake256Context
	if rc := FalconVerifyFinish(sig, SigCT, pk, &emptyHd, nil); rc != ErrFormat {
		t.Fatalf("FalconVerifyFinish mismatch hash data rc = %d", rc)
	}
	if rc := FalconVerifyFinish(sig, 99, pk, &hd, nil); rc != ErrBadArg {
		t.Fatalf("FalconVerifyFinish bad sigType rc = %d", rc)
	}
	badSigFormat := cloneBytesNative(sig)
	badSigFormat[0] = 0x39
	if rc := FalconVerifyFinish(badSigFormat, SigCT, pk, &hd, nil); rc != ErrFormat {
		t.Fatalf("FalconVerifyFinish mismatch sigFormat rc = %d", rc)
	}
	
	badSigFormatCT := cloneBytesNative(sig)
	badSigFormatCT[0] = 0x59
	if rc := FalconVerifyFinish(badSigFormatCT, SigPadded, pk, &hd, nil); rc != ErrFormat {
		t.Fatalf("FalconVerifyFinish mismatch sigFormat 2 rc = %d", rc)
	}

	if rc := FalconVerifyFinish(sig, 0, pk, &hd, nil); rc != 0 {
		t.Fatalf("FalconVerifyFinish auto-detect sigType rc = %d", rc)
	}
	if rc := FalconVerifyFinish(badSigFormat, 0, pk, &hd, nil); rc != ErrBadSig {
		t.Fatalf("FalconVerifyFinish auto-detect bad sigType rc = %d", rc)
	}

	// padCompressedForVerify coverage
	tooLongSig := make([]byte, SigPaddedSize(9)+1)
	if padCompressedForVerify(tooLongSig, 9) != nil {
		t.Fatalf("padCompressedForVerify should fail on too long sig")
	}

	// privateLogN / publicLogN coverage
	if privateLogN(nil) != -1 {
		t.Fatalf("privateLogN(nil) should fail")
	}
	if publicLogN(nil) != -1 {
		t.Fatalf("publicLogN(nil) should fail")
	}
	if privateLogN([]byte{0x51}) != -1 { // logn = 1
		t.Fatalf("privateLogN(1) should fail")
	}
	if publicLogN([]byte{0x01}) != -1 { // logn = 1
		t.Fatalf("publicLogN(1) should fail")
	}
}

func cloneBytesNative(src []byte) []byte {
	if len(src) == 0 {
		return nil
	}
	dst := make([]byte, len(src))
	copy(dst, src)
	return dst
}

