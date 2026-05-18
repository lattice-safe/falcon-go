//go:build !fndsa_fp_emu && (386.sse2 || amd64 || arm64 || riscv64) && !gccgo

package fndsa

import "math"

func f64_rint(x f64) int32 {
	return int32(math.RoundToEven(x))
}

func f64_floor(x f64) int32 {
	return int32(math.Floor(x))
}

func f64_sqrt(x f64) f64 {
	return math.Sqrt(x)
}
