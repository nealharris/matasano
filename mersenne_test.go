package matasano

import (
	"bytes"
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

func TestUndoRightMix(t *testing.T) {
	rand.Seed(time.Now().Unix())
	x := uint32(rand.Int31())

	// rightMix is not-invertible if the second arg is 0
	for i := 1; i < 32; i++ {
		rightMixed := rightMix(x, uint(i))
		undone := undoRightMix(rightMixed, uint(i))
		if undone != x {
			t.Errorf("Expected %v, but got %v, at index %v", x, undone, i)
		}
	}
}

func TestUndoLeftMix(t *testing.T) {
	rand.Seed(time.Now().Unix())
	x := uint32(rand.Int31())
	magic := uint32(rand.Int31())

	// leftMix is not-invertible if the second arg is 0
	for i := 1; i < 32; i++ {
		leftMixed := leftMix(x, magic, uint(i))
		undone := undoLeftMix(leftMixed, magic, uint(i))
		if undone != x {
			t.Errorf("Expected %v, but got %v, at index %v", x, undone, i)
		}
	}
}

func TestUntemper(t *testing.T) {
	rand.Seed(time.Now().Unix())
	x := uint32(rand.Int31())

	tempered := temper(x)
	untempered := untemper(tempered)

	if x != untempered {
		t.Errorf("expected %v, but got %v", x, untempered)
	}
}

func TestCloneMersenneTwister(t *testing.T) {
	rand.Seed(time.Now().Unix())
	seed := uint32(rand.Int31())

	mt := new(MersenneTwister)
	mt.Initialize(seed)

	var outputs [624]uint32
	for i := 0; i < 624; i++ {
		outputs[i] = mt.ExtractNumber()
	}

	cloned := CloneMersenneTwister(outputs)

	for i := 0; i < 624; i++ {
		if cloned.ExtractNumber() != mt.ExtractNumber() {
			t.Errorf("oh noes!")
		}
	}
}

func TestMersenneStreamCipherEncrypt(t *testing.T) {
	rand.Seed(time.Now().Unix())
	seed := rand.Int()
	length := rand.Intn(1000)
	pt := make([]byte, length)

	for i := 0; i < length; i++ {
		pt[i] = byte(rand.Intn(256))
	}

	if bytes.Compare(pt, MersenneStreamCipherEncrypt(seed, MersenneStreamCipherEncrypt(seed, pt))) != 0 {
		t.Errorf("Expected MersenneStreamCipherEncrypt to also decrypt")
	}
}

func TestRecoverSeedFromCipherText(t *testing.T) {
	rand.Seed(time.Now().Unix())
	seed := rand.Intn(1 << 16)
	length := rand.Intn(1000)

	pt := make([]byte, length+len(knownPt))
	for i := 0; i < length; i++ {
		pt[i] = byte(rand.Intn(256))
	}
	for i := 0; i < len(knownPt); i++ {
		pt[length+i] = knownPt[i]
	}

	ct := MersenneStreamCipherEncrypt(seed, pt)
	guessedSeed, err := RecoverSeedFromCipherText(ct)

	if err != nil {
		t.Errorf("error recovering seed: %v", err)
	}

	if seed != guessedSeed {
		t.Errorf("was supposed to get %v, but got %v", seed, guessedSeed)
	}
}
