package matasano

//import "crypto"
import "encoding/base64"
import "encoding/hex"
import "fmt"
import "errors"
//import "strings"
import "math"
import "bytes"

func HexToB64(s string) (string, error) {
	bytes, err := hex.DecodeString(s)
	if err != nil {
		fmt.Println("error: ", err)
		return "", err
	}
	return base64.StdEncoding.EncodeToString(bytes), nil
}

func B64ToHex(s string) (string, error) {
	bytes, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		fmt.Println("error: ", err)
		return "", err
	}
	return hex.EncodeToString(bytes), nil
}

func Xor(b1 []byte, b2 []byte) ([]byte, error) {
	if len(b1) != len(b2) {
		return nil, errors.New("byte arrays not the same length!") 
	}

	result := make([]byte, len(b1))

	for i := 0; i < len(b1); i ++ {
		result[i] = b1[i] ^ b2[i]
	}

	return result, nil
}

func SingleCharXor(b byte, s []byte) ([]byte, error) {
	repeated := bytes.Repeat([]byte{b}, len(s))
	return Xor(repeated, s)
}

func RuneFrequencies(b []byte) map[rune]float64 {
	counts := make(map[rune]int)
	for i := 0; i < len(b); i++ {
		counts[rune(b[i])]++
	}

	freqs := make(map[rune]float64)
	for ch := range(counts) {
		freqs[ch] = float64(counts[ch])/float64(len(b))
	}

	return freqs
}

// lower score means more likely to be English
func EnglishScore(b []byte) float64 {
	// copied from http://en.wikipedia.org/wiki/Letter_frequency on 3/11/2014
	expected_freqs := map[rune]float64{
		'a':0.08167,
		'b':0.01492,
		'c':0.02782,
		'd':0.04253,
		'e':0.12702,
		'f':0.02228,
		'g':0.02015,
		'h':0.06094,
		'i':0.06966,
		'j':0.00153,
		'k':0.00772,
		'l':0.04025,
		'm':0.02406,
		'n':0.06749,
		'o':0.07507,
		'p':0.01929,
		'q':0.00095,
		'r':0.05987,
		's':0.06327,
		't':0.09056,
		'u':0.02758,
		'v':0.00978,
		'w':0.02360,
		'x':0.00150,
		'y':0.01974,
		'z':0.00074,
	}

	score := float64(0)
	freqs := RuneFrequencies(b)

	for ch := range(freqs) {
		if expectedFreq, ok := expected_freqs[ch]; ok {
			score += math.Pow(freqs[ch] - expectedFreq, 2.0)
		} else {
			score += freqs[ch]
		}
		
	}

	return score
}

func FindSingleCharForXor(b []byte) byte {
	bestScore := float64(-1)
	bestChar := 'a'

	for ch := 'a'; ch <= 'z'; ch++ {
		Xored, _ := SingleCharXor(byte(ch), b)
		currentScore := EnglishScore(Xored)
		if currentScore < bestScore || bestScore < 0 {
			bestScore = currentScore
			bestChar = ch
		}
	}

	for ch := 'A'; ch <= 'Z'; ch++ {
		Xored, _ := SingleCharXor(byte(ch), b)
		currentScore := EnglishScore(Xored)
		if currentScore < bestScore || bestScore < 0 {
			bestScore = currentScore
			bestChar = ch
		}
	}

	return byte(bestChar)
}
