package native

import (
	"crypto/rand"
	"encoding/binary"
	"io"
)

// Prng is Falcon's ChaCha20-based PRNG state.
type Prng struct {
	buf   [512]byte
	ptr   int
	state [256]byte
}

// NewPrng returns a zeroed PRNG state.
func NewPrng() Prng {
	return Prng{}
}

// GetSeed fills seed with OS randomness.
func GetSeed(seed []byte) bool {
	if len(seed) == 0 {
		return true
	}
	_, err := io.ReadFull(rand.Reader, seed)
	return err == nil
}

// PrngInit initializes a PRNG from a flipped SHAKE256 context.
func PrngInit(p *Prng, src *Shake256Context) {
	var tmp [56]byte
	Shake256Extract(src, tmp[:])
	copy(p.state[:56], tmp[:])
	clear(tmp[:])
	PrngRefill(p)
}

var chachaConstant = [4]uint32{0x61707865, 0x3320646e, 0x79622d32, 0x6b206574}

// PrngRefill fills the 512-byte PRNG buffer with eight interleaved ChaCha20 blocks.
func PrngRefill(p *Prng) {
	cc := binary.LittleEndian.Uint64(p.state[48:56])
	var initState [12]uint32
	for i := 0; i < 12; i++ {
		initState[i] = binary.LittleEndian.Uint32(p.state[i*4 : i*4+4])
	}

	for u := uint64(0); u < 8; u++ {
		var st [16]uint32
		st[0] = chachaConstant[0]
		st[1] = chachaConstant[1]
		st[2] = chachaConstant[2]
		st[3] = chachaConstant[3]
		copy(st[4:], initState[:])

		counter := cc + u
		st[14] ^= uint32(counter)
		st[15] ^= uint32(counter >> 32)

		initial := st
		for i := 0; i < 10; i++ {
			chachaQuarterRound(&st, 0, 4, 8, 12)
			chachaQuarterRound(&st, 1, 5, 9, 13)
			chachaQuarterRound(&st, 2, 6, 10, 14)
			chachaQuarterRound(&st, 3, 7, 11, 15)
			chachaQuarterRound(&st, 0, 5, 10, 15)
			chachaQuarterRound(&st, 1, 6, 11, 12)
			chachaQuarterRound(&st, 2, 7, 8, 13)
			chachaQuarterRound(&st, 3, 4, 9, 14)
		}
		for i := 0; i < 16; i++ {
			st[i] += initial[i]
		}

		uIdx := int(u)
		for v := 0; v < 16; v++ {
			off := (uIdx << 2) + (v << 5)
			binary.LittleEndian.PutUint32(p.buf[off:off+4], st[v])
		}
	}

	binary.LittleEndian.PutUint64(p.state[48:56], cc+8)
	p.ptr = 0
}

func chachaQuarterRound(st *[16]uint32, a, b, c, d int) {
	st[a] += st[b]
	st[d] ^= st[a]
	st[d] = st[d]<<16 | st[d]>>16

	st[c] += st[d]
	st[b] ^= st[c]
	st[b] = st[b]<<12 | st[b]>>20

	st[a] += st[b]
	st[d] ^= st[a]
	st[d] = st[d]<<8 | st[d]>>24

	st[c] += st[d]
	st[b] ^= st[c]
	st[b] = st[b]<<7 | st[b]>>25
}

// PrngGetU64 returns a 64-bit random word.
func PrngGetU64(p *Prng) uint64 {
	u := p.ptr
	if u >= 512-9 {
		PrngRefill(p)
		return PrngGetU64(p)
	}
	p.ptr = u + 8
	return binary.LittleEndian.Uint64(p.buf[u : u+8])
}

// PrngGetU8 returns an 8-bit random value as uint32.
func PrngGetU8(p *Prng) uint32 {
	v := uint32(p.buf[p.ptr])
	p.ptr++
	if p.ptr == 512 {
		PrngRefill(p)
	}
	return v
}

// PrngGetBytes fills dst with PRNG output.
func PrngGetBytes(p *Prng, dst []byte) {
	off := 0
	remaining := len(dst)
	for remaining > 0 {
		clen := 512 - p.ptr
		if clen > remaining {
			clen = remaining
		}
		copy(dst[off:off+clen], p.buf[p.ptr:p.ptr+clen])
		off += clen
		remaining -= clen
		p.ptr += clen
		if p.ptr == 512 {
			PrngRefill(p)
		}
	}
}

// Clear zeroes the PRNG state.
func (p *Prng) Clear() {
	clear(p.buf[:])
	clear(p.state[:])
	p.ptr = 0
}
