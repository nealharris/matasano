package matasano

import (
	"math/rand"
	"testing"
	"time"
)

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

func TestSeedCrack(t *testing.T) {
	rangeSize := 100000
	rand.Seed(time.Now().Unix())
	min := uint32(rand.Int31())
	max := min + uint32(rangeSize)
	offset := uint32(rand.Intn(rangeSize))
	seed := min + offset

	mt := new(MersenneTwister)
	mt.Initialize(seed)
	output := mt.ExtractNumber()

	guess, err := CrackMersenneSeed(output, min, max)
	if err != nil {
		t.Errorf("error while trying to crack seed: %v", err)
	}

	if guess != seed {
		t.Errorf("guessed seed was %v, but it's actually %v", guess, seed)
	}
}
