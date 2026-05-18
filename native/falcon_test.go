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
}
