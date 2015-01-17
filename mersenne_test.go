package matasano

import "testing"

func TestMersenne(t *testing.T) {
	mt := new(MersenneTwister)
	// sample output taken from https://github.com/cslarsen/mersenne-twister
	mt.Initialize(1)
	expected := []uint32{1791095845, 4282876139, 3093770124, 4005303368, 491263, 550290313, 1298508491, 4290846341, 630311759, 1013994432}

	for index, element := range expected {
		val := mt.ExtractNumber()
		if val != element {
			t.Errorf("expected %v, but got %v at index %v", element, val, index)
		}
	}
}
