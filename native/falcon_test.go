package native

import "testing"

func TestSizeFunctions(t *testing.T) {
	tests := []struct {
		logn       uint
		priv, pub  int
		padded, ct int
	}{
		{9, 1281, 897, 666, 809},
		{10, 2305, 1793, 1280, 1577},
	}
	for _, tt := range tests {
		if got := PrivKeySize(tt.logn); got != tt.priv {
			t.Fatalf("PrivKeySize(%d) = %d, want %d", tt.logn, got, tt.priv)
		}
		if got := PubKeySize(tt.logn); got != tt.pub {
			t.Fatalf("PubKeySize(%d) = %d, want %d", tt.logn, got, tt.pub)
		}
		if got := SigPaddedSize(tt.logn); got != tt.padded {
			t.Fatalf("SigPaddedSize(%d) = %d, want %d", tt.logn, got, tt.padded)
		}
		if got := SigCTSize(tt.logn); got != tt.ct {
			t.Fatalf("SigCTSize(%d) = %d, want %d", tt.logn, got, tt.ct)
		}
	}

	if SigCompressedMaxSize(0) != 0 || SigPaddedSize(11) != 0 || SigCTSize(11) != 0 {
		t.Fatal("invalid logn signature sizes must return zero")
	}

	if PrivKeySize(3) != 25 || PubKeySize(1) != 5 || SigCTSize(3) != 52 || TmpSizeKeygen(3) != 303 {
		t.Fatal("small logn size helpers mismatch")
	}

	if got := TmpSizeKeygen(9); got != 15879 {
		t.Fatalf("TmpSizeKeygen(9) = %d, want 15879", got)
	}
	if got := TmpSizeSignDyn(9); got != 39943 {
		t.Fatalf("TmpSizeSignDyn(9) = %d, want 39943", got)
	}
	if got := TmpSizeSignTree(9); got != 25607 {
		t.Fatalf("TmpSizeSignTree(9) = %d, want 25607", got)
	}
	if got := TmpSizeVerify(9); got != 4097 {
		t.Fatalf("TmpSizeVerify(9) = %d, want 4097", got)
	}
	if got := TmpSizeExpandPriv(9); got != 26631 {
		t.Fatalf("TmpSizeExpandPriv(9) = %d", got)
	}
	if got := ExpandedKeySize(9); got != 57344 {
		t.Fatalf("ExpandedKeySize(9) = %d", got)
	}
}

func TestCommonCoverage(t *testing.T) {
	// reduceHashPointWord coverage
	w1 := reduceHashPointWord(61445) // expected out of bounds logic
	if w1 == 0 {
		t.Log("tested reduceHashPointWord out of bound")
	}

	// HashToPointCT coverage
	var sc Shake256Context
	Shake256InitPRNGFromSeed(&sc, []byte("test-hash-to-point"))
	Shake256Flip(&sc)
	x := make([]uint16, 512)
	HashToPointCT(&sc, x, 9, nil)
	if x[0] == 0 && x[1] == 0 {
		t.Fatal("HashToPointCT produced zeros")
	}

	// IsShortHalf coverage
	s2 := make([]int16, 512)
	s2[0] = 100
	if !IsShortHalf(1000, s2, 9) {
		t.Fatal("IsShortHalf should be true for small values")
	}
	s2[0] = 30000 // Very large to exceed L2 bound
	if IsShortHalf(1000, s2, 9) {
		t.Fatal("IsShortHalf should be false for large values")
	}
}
