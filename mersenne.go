package matasano

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

// ExtractNumber produces a tempered pseudorandom number based on the index-th
// value calling generate_numbers() every 624 numbers
func (mt *MersenneTwister) ExtractNumber() uint32 {
	if mt.index == 0 {
		mt.generateNumbers()
	}

	y := mt.state[mt.index]
	y = y ^ (y >> 11)
	y = y ^ ((y << 7) & 2636928640)
	y = y ^ ((y << 15) & 4022730752)
	y = y ^ (y >> 18)

	mt.index = ((mt.index + 1) % 624)

	return uint32(y)
}
