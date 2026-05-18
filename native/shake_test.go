package native

import (
	"bytes"
	"encoding/hex"
	"testing"
)

func TestShake256KATEmpty(t *testing.T) {
	expected := mustHex(t, "46b9dd2b0ba88d13233b3feb743eeb243fcd52ea62b81b82b50c27646ed5762fd75dc4ddd8c0f200cb05019d67b592f6fc821c49479ab48640292eacb3b7c4be")
	var sc Shake256Context
	Shake256Init(&sc)
	Shake256Flip(&sc)
	out := make([]byte, len(expected))
	Shake256Extract(&sc, out)
	if !bytes.Equal(out, expected) {
		t.Fatalf("SHAKE256(empty) = %x, want %x", out, expected)
	}
}

func TestShake256KATShort(t *testing.T) {
	input := mustHex(t, "8d8001e2c096f1b88e7c9224a086efd4797fbf74a8033a2d422a2b6b8f6747e4")
	expected := mustHex(t,
		"2e975f6a8a14f0704d51b13667d8195c219f71e6345696c49fa4b9d08e9225d3"+
			"d39393425152c97e71dd24601c11abcfa0f12f53c680bd3ae757b8134a9c10d42"+
			"9615869217fdd5885c4db174985703a6d6de94a667eac3023443a8337ae1bc601"+
			"b76d7d38ec3c34463105f0d3949d78e562a039e4469548b609395de5a4fd43c46"+
			"ca9fd6ee29ada5efc07d84d553249450dab4a49c483ded250c9338f85cd937ae6"+
			"6bb436f3b4026e859fda1ca571432f3bfc09e7c03ca4d183b741111ca0483d0ed"+
			"abc03feb23b17ee48e844ba2408d9dcfd0139d2e8c7310125aee801c61ab7900d"+
			"1efc47c078281766f361c5e6111346235e1dc38325666c")

	var sc Shake256Context
	Shake256Init(&sc)
	Shake256Inject(&sc, input)
	Shake256Flip(&sc)
	out := make([]byte, len(expected))
	Shake256Extract(&sc, out)
	if !bytes.Equal(out, expected) {
		t.Fatalf("SHAKE256(short) = %x, want %x", out, expected)
	}
}

func TestShake256IncrementalExtract(t *testing.T) {
	expected := mustHex(t, "46b9dd2b0ba88d13233b3feb743eeb243fcd52ea62b81b82b50c27646ed5762fd75dc4ddd8c0f200cb05019d67b592f6fc821c49479ab48640292eacb3b7c4be")
	var sc Shake256Context
	Shake256Init(&sc)
	Shake256Flip(&sc)
	out := make([]byte, len(expected))
	for i := range out {
		Shake256Extract(&sc, out[i:i+1])
	}
	if !bytes.Equal(out, expected) {
		t.Fatalf("SHAKE256 incremental = %x, want %x", out, expected)
	}
}

func mustHex(t *testing.T, s string) []byte {
	t.Helper()
	out, err := hex.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	return out
}
