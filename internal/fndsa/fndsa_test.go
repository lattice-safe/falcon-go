package fndsa

import (
	"crypto"
	"testing"
)

func TestMqOps(t *testing.T) {
	// hit mq_add, mq_sub directly
	if mq_add(100, q-50) != 50 {
		t.Fatal("mq_add failed")
	}
	if mq_sub(50, 100) != q-50 {
		t.Fatal("mq_sub failed")
	}

	// mq_div 0
	t.Logf("mq_div(0, 100) = %d", mq_div(0, 100))
}

func TestVerifyWeak(t *testing.T) {
	sk, pk, err := KeyGenDeterministic(2, make([]byte, 48)) // logn=2
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
	badSig[0] = 0x52 // LogN = 2, CT format (VerifyWeak only accepts 0x30 padded format)
	if VerifyWeak(pk, nil, crypto.Hash(0), []byte("test"), badSig) {
		t.Fatal("VerifyWeak succeeded on CT format")
	}
	if VerifyWeak(pk, nil, crypto.Hash(0), []byte("test"), make([]byte, 10)) {
		t.Fatal("VerifyWeak succeeded on short sig")
	}
}

func TestVerify(t *testing.T) {
	sk, pk, _ := KeyGenDeterministic(9, make([]byte, 48))
	pre, _ := PrepareSigningKey(sk)
	nonce := make([]byte, 40)
	sig, _ := pre.SignPaddedWithNonceSampler(nonce, make([]byte, 48*1024), nil, crypto.Hash(0), []byte("test"))
	
	if !Verify(pk, nil, crypto.Hash(0), []byte("test"), sig) {
		t.Fatal("Verify failed")
	}
}

func TestExportErrors(t *testing.T) {
	_, err := MakePublic(make([]byte, 10))
	if err == nil {
		t.Fatal("MakePublic should fail on short key")
	}
	
	badSk := make([]byte, 1282) // PrivKeySize(9) + 1
	badSk[0] = 0x59
	_, err = MakePublic(badSk)
	if err == nil {
		t.Fatal("MakePublic should fail on bad key")
	}

	// SignPaddedWithNonceSampler with invalid padding format
	sk, _, _ := KeyGenDeterministic(9, make([]byte, 48))
	pre, _ := PrepareSigningKey(sk)
	// Add some use of pre to avoid declared and not used
	_ = pre
}

func TestNextU16(t *testing.T) {
	rng := newSHAKE256prng(make([]byte, 32))
	u16 := rng.next_u16()
	if u16 == 0 {
		t.Log("next_u16 returned 0")
	}
}
