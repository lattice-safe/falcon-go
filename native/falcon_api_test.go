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
