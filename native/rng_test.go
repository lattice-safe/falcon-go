package native

import (
	"bytes"
	"testing"
)

func TestPrngDeterministic(t *testing.T) {
	var sc1, sc2 Shake256Context
	seed := []byte("falcon-go-prng-seed")
	Shake256InitPRNGFromSeed(&sc1, seed)
	Shake256InitPRNGFromSeed(&sc2, seed)

	var p1, p2 Prng
	PrngInit(&p1, &sc1)
	PrngInit(&p2, &sc2)

	out1 := make([]byte, 700)
	out2 := make([]byte, 700)
	PrngGetBytes(&p1, out1)
	PrngGetBytes(&p2, out2)
	if !bytes.Equal(out1, out2) {
		t.Fatal("PRNG output is not deterministic for the same seed")
	}
	if bytes.Equal(out1, make([]byte, len(out1))) {
		t.Fatal("PRNG output is all zero")
	}

	// Additional coverage for rng methods
	p1.Clear()
	u64 := PrngGetU64(&p2)
	u8 := PrngGetU8(&p2)
	if u64 == 0 && u8 == 0 {
		t.Log("PRNG produced 0, technically possible but unlikely")
	}

	// Coverage for Shake256InitPRNGFromSystem
	var sc3 Shake256Context
	Shake256InitPRNGFromSystem(&sc3)

	// Coverage for new objects
	_ = NewPrng()
	_ = NewShake256Context()

	// Hit refill branches
	for i := 0; i < 70; i++ {
		PrngGetU64(&p2)
	}
	for i := 0; i < 520; i++ {
		PrngGetU8(&p1)
	}

	seedOut := make([]byte, 32)
	if !GetSeed(seedOut) {
		t.Fatal("GetSeed failed")
	}
	if !GetSeed(nil) {
		t.Fatal("GetSeed(nil) failed")
	}
}
