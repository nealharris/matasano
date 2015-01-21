package matasano

import "errors"

// MersenneTwister is a PRNG.  It produces an integer in the range
// range [0, 2^32 - 1]
type MersenneTwister struct {
	state [624]uint32
	index int
}

// Initialize is the method which accepts the seed for the MT PRNG.  It is
// expected that the client will call this method before using ExtractNumber.
func (mt *MersenneTwister) Initialize(seed uint32) {
	mt.index = 0
	mt.state[0] = seed

	for i := uint32(1); i < uint32(len(mt.state)); i++ {
		mt.state[i] = uint32(1812433253*(mt.state[i-1]^(mt.state[i-1]>>30)) + i)
	}
}

func (mt *MersenneTwister) generateNumbers() {
	for index, element := range mt.state {
		y := (element & 0x80000000) + (mt.state[(index+1)%len(mt.state)] & 0x7fffffff)

		mt.state[index] = mt.state[(index+397)%len(mt.state)] ^ (y >> 1)

		if y%2 != 0 {
			mt.state[index] = mt.state[index] ^ 2567483615
		}
	}
}

func (mt *MersenneTwister) setState(state [624]uint32) {
	mt.state = state
}

func (mt *MersenneTwister) setIndex(index int) {
	mt.index = index
}

// ExtractNumber produces a tempered pseudorandom number based on the index-th
// value calling generate_numbers() every 624 numbers
func (mt *MersenneTwister) ExtractNumber() uint32 {
	if mt.index == 0 {
		mt.generateNumbers()
	}

	output := temper(mt.state[mt.index])
	mt.index = ((mt.index + 1) % 624)
	return output
}

func temper(input uint32) uint32 {
	output := rightMix(input, 11)
	output = leftMix(output, 2636928640, 7)
	output = leftMix(output, 4022730752, 15)
	output = rightMix(output, 18)

	return output
}

func untemper(input uint32) uint32 {
	output := undoRightMix(input, 18)
	output = undoLeftMix(output, 4022730752, 15)
	output = undoLeftMix(output, 2636928640, 7)
	output = undoRightMix(output, 11)

	return output
}

func rightMix(input uint32, shift uint) uint32 {
	return input ^ (input >> shift)
}

func undoRightMix(input uint32, shift uint) uint32 {
	output := input

	for i := 31 - int(shift); i >= 0; i-- {
		if hasBit(output, uint(i)) != hasBit(output, uint(i)+shift) {
			output = setBit(output, uint(i))
		} else {
			output = clearBit(output, uint(i))
		}
	}

	return output
}

func leftMix(input, magic uint32, shift uint) uint32 {
	return input ^ ((input << shift) & magic)
}

func undoLeftMix(input, magic uint32, shift uint) uint32 {
	output := input

	for i := shift; i < 32; i++ {
		lowerBit := hasBit(output, uint(i)-shift)
		magicBit := hasBit(magic, i)
		xored := lowerBit && magicBit

		if hasBit(output, uint(i)) != xored {
			output = setBit(output, uint(i))
		} else {
			output = clearBit(output, uint(i))
		}
	}

	return output
}

func setBit(n uint32, pos uint) uint32 {
	n |= (1 << pos)
	return n
}

func clearBit(n uint32, pos uint) uint32 {
	mask := ^(1 << pos)
	n &= uint32(mask)
	return n
}

func hasBit(n uint32, pos uint) bool {
	val := n & (1 << pos)
	return (val > 0)
}

// CrackMersenneSeed takes the first output of the MT19937 PRNG, a min and max
// value for the seed, and returns a seed in that range that produces that
// output.  If no such seed is found, an error is returned.
func CrackMersenneSeed(prngOutput uint32, min, max uint32) (uint32, error) {
	for i := min; i <= max; i++ {
		mt := new(MersenneTwister)
		mt.Initialize(i)
		if mt.ExtractNumber() == prngOutput {
			return i, nil
		}
	}

	return 0, errors.New("no seed in the given range produces the given output")
}

// CloneMersenneTwister performs the attack described at
// http://cryptopals.com/sets/3/challenges/23/.  It takes the first 624 outputs
// of a MT19937 PRNG, and produces a clone of that MT19937 instance that
// produced that output.
func CloneMersenneTwister(mtOutput [624]uint32) *MersenneTwister {
	var state [624]uint32
	for i := 0; i < 624; i++ {
		state[i] = untemper(mtOutput[i])
	}

	mt := new(MersenneTwister)
	mt.setState(state)
	mt.setIndex(0)

	return mt
}
