package native

const (
	ErrRandom     = -1
	ErrSize       = -2
	ErrFormat     = -3
	ErrBadSig     = -4
	ErrBadArg     = -5
	ErrInternal   = -6
	SigCompressed = 1
	SigPadded     = 2
	SigCT         = 3
)

func PrivKeySize(logn uint) int {
	if logn <= 3 {
		return 3<<logn + 1
	}
	return int((10-(logn>>1))<<(logn-2)) + (1 << logn) + 1
}

func PubKeySize(logn uint) int {
	if logn <= 1 {
		return 5
	}
	return int(7<<(logn-2)) + 1
}

func SigCompressedMaxSize(logn uint) int {
	if logn < 1 || logn > 10 {
		return 0
	}
	return int((((11 << logn) + (101 >> (10 - logn)) + 7) >> 3) + 41)
}

func SigPaddedSize(logn uint) int {
	if logn < 1 || logn > 10 {
		return 0
	}
	return int(44 + 3*(256>>(10-logn)) +
		2*(128>>(10-logn)) +
		3*(64>>(10-logn)) +
		2*(16>>(10-logn)) -
		2*(2>>(10-logn)) -
		8*(1>>(10-logn)))
}

func SigCTSize(logn uint) int {
	if logn < 1 || logn > 10 {
		return 0
	}
	base := int(3<<(logn-1)) + 41
	if logn == 3 {
		return base - 1
	}
	return base
}

func TmpSizeKeygen(logn uint) int {
	if logn <= 3 {
		return 272 + (3 << logn) + 7
	}
	return int(28<<logn) + (3 << logn) + 7
}

func TmpSizeMakePub(logn uint) int {
	return int(6<<logn) + 1
}

func TmpSizeSignDyn(logn uint) int {
	return int(78<<logn) + 7
}

func TmpSizeSignTree(logn uint) int {
	return int(50<<logn) + 7
}

func TmpSizeExpandPriv(logn uint) int {
	return int(52<<logn) + 7
}

func ExpandedKeySize(logn uint) int {
	return int((8*logn + 40) << logn)
}

func TmpSizeVerify(logn uint) int {
	return int(8<<logn) + 1
}
