package native

import (
	"reflect"
	"testing"
)

func TestHashToPointVarTime(t *testing.T) {
	const logn = 4
	n := 1 << logn
	msg := []byte("test message for Falcon")
	nonce := bytesRepeat(0x42, 40)

	var sc Shake256Context
	Shake256Init(&sc)
	Shake256Inject(&sc, nonce)
	Shake256Inject(&sc, msg)
	Shake256Flip(&sc)

	hm := make([]uint16, n)
	HashToPointVarTime(&sc, hm, logn)
	for i, v := range hm {
		if v >= 12289 {
			t.Fatalf("hash-to-point value %d at %d is out of range", v, i)
		}
	}

	var sc2 Shake256Context
	Shake256Init(&sc2)
	Shake256Inject(&sc2, nonce)
	Shake256Inject(&sc2, msg)
	Shake256Flip(&sc2)
	hm2 := make([]uint16, n)
	HashToPointVarTime(&sc2, hm2, logn)
	if !reflect.DeepEqual(hm, hm2) {
		t.Fatal("HashToPointVarTime is not deterministic")
	}
}

func TestIsShort(t *testing.T) {
	const logn = 4
	n := 1 << logn
	s1 := make([]int16, n)
	s2 := make([]int16, n)
	for i := 0; i < n; i++ {
		s1[i] = int16(i - 8)
		s2[i] = int16(8 - i)
	}
	if !IsShort(s1, s2, logn) {
		t.Fatal("small vectors should be short")
	}
	for i := 0; i < n; i++ {
		s1[i] = 2047
		s2[i] = 2047
	}
	if IsShort(s1, s2, logn) {
		t.Fatal("large vectors should not be short")
	}
}

func bytesRepeat(b byte, n int) []byte {
	out := make([]byte, n)
	for i := range out {
		out[i] = b
	}
	return out
}
