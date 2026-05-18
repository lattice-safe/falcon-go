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
}
