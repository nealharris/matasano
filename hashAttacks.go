package matasano

import "github.com/nealharris/sha1"

func convertShaToH(sha [20]byte) [5]uint32 {
	var h [5]uint32
	for i := 0; i < 5; i++ {
		h[i] = uint32(sha[i*4])<<24 | uint32(sha[i*4+1])<<16 | uint32(sha[i*4+2])<<8 | uint32(sha[i*4+3])
	}

	return h
}

// ForgeKeyedSha will perform a length extension attack.  Given a known
// signature sha, and a target message, this will produce a sha which is the
// keyed hash of the original message appended with some 'glue padding', and
// further appended with the target message.
// See http://cryptopals.com/sets/4/challenges/29/ for details
func ForgeKeyedSha(targetMessage []byte, knownSha [20]byte, knownLength int) [20]byte {
	return sha1.SumWithInitialState(targetMessage, convertShaToH(knownSha), knownLength)
}

func mdPad(data []byte) []byte {
	l := len(data)
	var tmp [64]byte
	tmp[0] = 0x80

	zeroPadded := make([]byte, 64)

	// pad with a single 1, and a bunch of 0's so that the length is 56 mod 64
	if l%64 < 56 {
		zeroPadded = append(data, tmp[0:56-l%64]...)
	} else {
		zeroPadded = append(data, tmp[0:64+56-len(data)%64]...)
	}

	// append the length of the original data
	l <<= 3
	for i := uint(0); i < 8; i++ {
		tmp[i] = byte(l >> (56 - 8*i))
	}

	return append(zeroPadded, tmp[0:8]...)
}
