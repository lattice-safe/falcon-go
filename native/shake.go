package native

import "math/bits"

const shake256Rate = 136

var keccakRoundConstants = [24]uint64{
	0x0000000000000001,
	0x0000000000008082,
	0x800000000000808a,
	0x8000000080008000,
	0x000000000000808b,
	0x0000000080000001,
	0x8000000080008081,
	0x8000000000008009,
	0x000000000000008a,
	0x0000000000000088,
	0x0000000080008009,
	0x000000008000000a,
	0x000000008000808b,
	0x800000000000008b,
	0x8000000000008089,
	0x8000000000008003,
	0x8000000000008002,
	0x8000000000000080,
	0x000000000000800a,
	0x800000008000000a,
	0x8000000080008081,
	0x8000000000008080,
	0x0000000080000001,
	0x8000000080008008,
}

var keccakRhoOffsets = [24]uint{
	1, 3, 6, 10, 15, 21, 28, 36, 45, 55, 2, 14,
	27, 41, 56, 8, 25, 43, 62, 18, 39, 61, 20, 44,
}

var keccakPiLane = [24]int{
	10, 7, 11, 17, 18, 3, 5, 16, 8, 21, 24, 4,
	15, 23, 19, 13, 12, 2, 20, 14, 22, 9, 6, 1,
}

// Shake256Context matches Falcon's inner SHAKE256 context shape.
type Shake256Context struct {
	st         [25]uint64
	dptr       uint64
	transcript []byte
	flipped    bool
	extracted  int
}

// NewShake256Context returns a zero-initialized SHAKE256 context.
func NewShake256Context() Shake256Context {
	return Shake256Context{}
}

// Shake256Init initializes a SHAKE256 context.
func Shake256Init(sc *Shake256Context) {
	*sc = Shake256Context{}
}

// Shake256Inject absorbs data into a SHAKE256 context.
func Shake256Inject(sc *Shake256Context, data []byte) {
	if !sc.flipped && len(data) != 0 {
		sc.transcript = append(sc.transcript, data...)
	}
	dptr := int(sc.dptr)
	off := 0
	remaining := len(data)

	for remaining > 0 {
		clen := shake256Rate - dptr
		if clen > remaining {
			clen = remaining
		}
		for i := 0; i < clen; i++ {
			v := dptr + i
			sc.st[v>>3] ^= uint64(data[off+i]) << uint((v&7)<<3)
		}
		dptr += clen
		off += clen
		remaining -= clen
		if dptr == shake256Rate {
			keccakF1600(&sc.st)
			dptr = 0
		}
	}
	sc.dptr = uint64(dptr)
}

// Shake256Flip switches a SHAKE256 context from absorb to squeeze mode.
func Shake256Flip(sc *Shake256Context) {
	v := int(sc.dptr)
	sc.st[v>>3] ^= uint64(0x1f) << uint((v&7)<<3)
	sc.st[16] ^= uint64(0x80) << 56
	sc.dptr = shake256Rate
	sc.flipped = true
}

// Shake256Extract squeezes bytes from a flipped SHAKE256 context.
func Shake256Extract(sc *Shake256Context, out []byte) {
	sc.extracted += len(out)
	dptr := int(sc.dptr)
	off := 0
	remaining := len(out)

	for remaining > 0 {
		if dptr == shake256Rate {
			keccakF1600(&sc.st)
			dptr = 0
		}
		clen := shake256Rate - dptr
		if clen > remaining {
			clen = remaining
		}
		for i := 0; i < clen; i++ {
			v := dptr + i
			out[off+i] = byte(sc.st[v>>3] >> uint((v&7)<<3))
		}
		dptr += clen
		off += clen
		remaining -= clen
	}
	sc.dptr = uint64(dptr)
}

// Shake256InitPRNGFromSeed initializes SHAKE256 as a deterministic PRNG.
func Shake256InitPRNGFromSeed(sc *Shake256Context, seed []byte) {
	Shake256Init(sc)
	Shake256Inject(sc, seed)
	Shake256Flip(sc)
}

// Shake256InitPRNGFromSystem initializes SHAKE256 from OS randomness.
func Shake256InitPRNGFromSystem(sc *Shake256Context) int {
	var seed [48]byte
	if !GetSeed(seed[:]) {
		return ErrRandom
	}
	Shake256InitPRNGFromSeed(sc, seed[:])
	clear(seed[:])
	return 0
}

func keccakF1600(a *[25]uint64) {
	var bc [5]uint64
	for round := 0; round < 24; round++ {
		for i := 0; i < 5; i++ {
			bc[i] = a[i] ^ a[i+5] ^ a[i+10] ^ a[i+15] ^ a[i+20]
		}
		for i := 0; i < 5; i++ {
			t := bc[(i+4)%5] ^ bits.RotateLeft64(bc[(i+1)%5], 1)
			for j := 0; j < 25; j += 5 {
				a[j+i] ^= t
			}
		}

		t := a[1]
		for i := 0; i < 24; i++ {
			j := keccakPiLane[i]
			bc[0] = a[j]
			a[j] = bits.RotateLeft64(t, int(keccakRhoOffsets[i]))
			t = bc[0]
		}

		for j := 0; j < 25; j += 5 {
			for i := 0; i < 5; i++ {
				bc[i] = a[j+i]
			}
			for i := 0; i < 5; i++ {
				a[j+i] ^= (^bc[(i+1)%5]) & bc[(i+2)%5]
			}
		}

		a[0] ^= keccakRoundConstants[round]
	}
}
