package matasano

import (
	"bytes"
	"crypto/aes"
	cryptorand "crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"math"
	mathrand "math/rand"
	"reflect"
	"time"
)

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
		return nil, errors.New("byte arrays not the same length")
	}

	result := make([]byte, len(b1))

	for i := 0; i < len(b1); i++ {
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
	for ch := range counts {
		freqs[ch] = float64(counts[ch]) / float64(len(b))
	}

	return freqs
}

// lower score means more likely to be English
func EnglishScore(b []byte) float64 {
	// copied from http://en.wikipedia.org/wiki/Letter_frequency on 3/11/2014
	expectedFreqs := map[rune]float64{
		'a': 0.08167,
		'b': 0.01492,
		'c': 0.02782,
		'd': 0.04253,
		'e': 0.12702,
		'f': 0.02228,
		'g': 0.02015,
		'h': 0.06094,
		'i': 0.06966,
		'j': 0.00153,
		'k': 0.00772,
		'l': 0.04025,
		'm': 0.02406,
		'n': 0.06749,
		'o': 0.07507,
		'p': 0.01929,
		'q': 0.00095,
		'r': 0.05987,
		's': 0.06327,
		't': 0.09056,
		'u': 0.02758,
		'v': 0.00978,
		'w': 0.02360,
		'x': 0.00150,
		'y': 0.01974,
		'z': 0.00074,
	}

	score := float64(0)
	freqs := RuneFrequencies(b)

	for ch := range freqs {
		if expectedFreq, ok := expectedFreqs[ch]; ok {
			score += math.Pow(freqs[ch]-expectedFreq, 2.0)
		} else {
			score += freqs[ch]
		}

	}

	return score
}

func FindSingleCharForXor(b []byte) byte {
	bestScore := float64(-1)
	var bestChar byte

	for ch := 0; ch <= 255; ch++ {
		Xored, _ := SingleCharXor(byte(ch), b)
		currentScore := EnglishScore(Xored)
		if currentScore < bestScore || bestScore < 0 {
			bestScore = currentScore
			bestChar = byte(ch)
		}
	}

	return byte(bestChar)
}

func DetectSingleCharXor(candidates [][]byte) ([]byte, byte) {
	bestScore := float64(-1)
	var bestString []byte
	var bestChar byte

	for i := 0; i < len(candidates); i++ {
		if len(candidates[i]) == 0 {
			continue
		}

		ch := FindSingleCharForXor(candidates[i])
		Xored, _ := SingleCharXor(ch, candidates[i])
		score := EnglishScore(Xored)

		if score < bestScore || bestScore < 0 {
			bestScore = score
			bestString = candidates[i]
			bestChar = ch
		}
	}

	return bestString, bestChar
}

func ExtendByteArray(b []byte, length int) []byte {
	currentLength := len(b)
	extended := bytes.Repeat(b, length/currentLength)
	return append(extended, b[0:length%currentLength]...)
}

func RepeatingKeyXor(key, plaintext []byte) []byte {
	extendedKey := ExtendByteArray(key, len(plaintext))
	result, _ := Xor(extendedKey, plaintext)
	return result
}

func HammingDistance(b1, b2 []byte) (int, error) {
	hd := 0
	if len(b1) != len(b2) {
		return 0, errors.New("cannot xor byte arrays of different lengths")
	}
	for i := 0; i < len(b1); i++ {
		for xor := b1[i] ^ b2[i]; xor != 0; xor = xor >> 1 {
			if xor&1 != 0 {
				hd++
			}
		}
	}

	return hd, nil
}

func FindBestKeySize(b []byte, min, max int) int {
	currentBestNormalizedHammingDistance := float64(-1)
	currentBestKeyLength := 0
	for i := min; i <= max; i++ {
		if 4*i > len(b) {
			break
		}
		hd1, _ := HammingDistance(b[0:i], b[i:2*i])
		hd2, _ := HammingDistance(b[0:i], b[2*i:3*i])
		hd3, _ := HammingDistance(b[0:i], b[3*i:4*i])
		hd4, _ := HammingDistance(b[i:2*i], b[2*i:3*i])
		hd5, _ := HammingDistance(b[i:2*i], b[3*i:4*i])
		hd6, _ := HammingDistance(b[2*i:3*i], b[3*i:4*i])
		normalized := float64(hd1+hd2+hd3+hd4+hd5+hd6) / float64(i)

		if normalized < currentBestNormalizedHammingDistance || currentBestNormalizedHammingDistance < 0 {
			currentBestNormalizedHammingDistance = normalized
			currentBestKeyLength = i
		}
	}

	return currentBestKeyLength
}

func Transpose(b []byte, blockSize int) [][]byte {
	leftover := len(b) % blockSize
	defaultLength := len(b) / blockSize
	blocks := make([][]byte, blockSize)
	for index, _ := range blocks {
		if index < leftover {
			blocks[index] = make([]byte, defaultLength+1)
		} else {
			blocks[index] = make([]byte, defaultLength)
		}
	}

	for index, element := range b {
		blocks[index%blockSize][index/blockSize] = element
	}

	return blocks
}

func EcbDecrypt(key, ct []byte) []byte {
	cipher, _ := aes.NewCipher(key)
	numBlocks := len(ct) / 16
	pt := make([]byte, len(ct))

	for i := 0; i < numBlocks; i++ {
		cipher.Decrypt(pt[16*i:16*(i+1)], ct[16*i:16*(i+1)])
	}

	return pt
}

func EcbEncrypt(key, pt []byte) []byte {
	// first, pad plaintext with null bytes
	var paddedPt []byte
	leftOver := len(pt) % 16
	if leftOver != 0 {
		paddedPt = make([]byte, len(pt)+16-leftOver)
	} else {
		paddedPt = make([]byte, len(pt))
	}
	copy(paddedPt, pt)

	cipher, _ := aes.NewCipher(key)
	numBlocks := len(paddedPt) / 16
	ct := make([]byte, numBlocks*16)

	for i := 0; i < numBlocks; i++ {
		cipher.Encrypt(ct[16*i:16*(i+1)], paddedPt[16*i:16*(i+1)])
	}

	return ct
}

func HasRepeatedBlock(ct []byte, blockSize int) bool {
	blocks := SplitIntoBlocks(ct, blockSize)
	set := make(map[string]bool)
	for _, block := range blocks {
		if set[string(block)] {
			return true
		}
		set[string(block)] = true
	}

	return false
}

func SplitIntoBlocks(b []byte, blockSize int) [][]byte {
	l := len(b)
	var res [][]byte
	if l%blockSize != 0 {
		res = make([][]byte, l/blockSize+1)
	} else {
		res = make([][]byte, l/blockSize)
	}

	for i := 0; i < len(res); i++ {
		res[i] = make([]byte, blockSize)
		for j := 0; j < blockSize; j++ {
			if i*blockSize+j >= len(b) {
				return res
			} else {
				res[i][j] = b[i*blockSize+j]
			}
		}
	}

	return res
}

func PKCS7Pad(b []byte, size int) []byte {
	padding := size - len(b)

	result := make([]byte, size)
	copy(result, b)

	for i := len(b); i < len(result); i++ {
		result[i] = byte(padding)
	}

	return result
}

func CbcEncrypt(key, pt, iv []byte) []byte {
	numBlocks := len(pt) / 16
	if len(pt)%16 != 0 {
		numBlocks++
	}
	ct := make([]byte, numBlocks*16)
	paddedPt := make([]byte, numBlocks*16)
	copy(paddedPt, pt)

	nextXor := iv
	cipher, _ := aes.NewCipher(key)

	var xored []byte
	for i := 0; i < numBlocks; i++ {
		xored, _ = Xor(nextXor, paddedPt[16*i:16*(i+1)])
		cipher.Encrypt(ct[16*i:16*(i+1)], xored)
		nextXor = ct[16*i : 16*(i+1)]
	}

	return ct
}

func CbcDecrypt(key, ct, iv []byte) []byte {
	numBlocks := len(ct) / 16
	if len(ct)%16 != 0 {
		numBlocks++
	}
	pt := make([]byte, numBlocks*16)

	cipher, _ := aes.NewCipher(key)

	preXor := make([]byte, 16)

	for i := 0; i < numBlocks; i++ {
		cipher.Decrypt(preXor, ct[16*i:16*(i+1)])
		if i > 0 {
			xored, _ := Xor(preXor, ct[16*(i-1):16*i])
			copy(pt[16*i:16*(i+1)], xored)
		} else {
			xored, _ := Xor(preXor, iv)
			copy(pt[0:16], xored)
		}
	}

	return pt
}

// Block cipher mode flags.
const (
	ECB = iota
	CBC
)

type oracle func(pt []byte) (ct []byte)

// The following method will use a randomly generated key to encrypt
// the input plaintext under either CBC or ECB mode (determined by a coin toss).
func EncryptionOracleCoinToss(pt []byte) []byte {
	var ct []byte
	key := make([]byte, 16)
	cryptorand.Read(key)

	pt = PadWithRandomBytes(pt, 5, 10)

	blockCipherMode := mathrand.Intn(2)
	if blockCipherMode == ECB {
		ct = EcbEncrypt(key, pt)
	} else {
		// Do CBC
		iv := make([]byte, 16)
		cryptorand.Read(iv)
		ct = CbcEncrypt(key, pt, iv)
	}

	return ct
}

func PadWithRandomBytes(buffer []byte, min, max int) []byte {
	mathrand.Seed(time.Now().Unix())
	numPrependBytes := mathrand.Intn(max-min) + min
	numAppendBytes := mathrand.Intn(max-min) + min

	prependBytes := make([]byte, numPrependBytes)
	appendBytes := make([]byte, numAppendBytes)

	cryptorand.Read(prependBytes)
	cryptorand.Read(appendBytes)

	return append(append(prependBytes, buffer...), appendBytes...)
}

// Attempts to guess the mode for the EncryptionOracle
// Returns a boolean describing whether or not it succeeded
func EncryptionModeDetector(encryptor oracle) int {
	pt := make([]byte, 64)
	ct := encryptor(pt)
	guessedMode := CBC

	blocks := SplitIntoBlocks(ct, 16)
	for i := 0; i < len(ct)/16; i++ {
		if i > 0 && reflect.DeepEqual(blocks[i], blocks[i-1]) {
			guessedMode = ECB
			break
		}
	}

	return guessedMode
}

const fixedKeyString = "b80b215a9d87206e3fb1d40baf255a81"
const targetB64PlainText = "Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRv" +
	"d24gc28gbXkgaGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBv" +
	"biBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvIHNheSBoaQpEaWQg" +
	"eW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK"

func ByteAtATimeECBEncryptor(pt []byte) []byte {
	key, _ := hex.DecodeString(fixedKeyString)
	targetBytes, _ := base64.StdEncoding.DecodeString(targetB64PlainText)

	return EcbEncrypt(key, append(pt, targetBytes...))
}

func DiscoverBlockSizeOfEncryptionOracle(encryptor oracle) int {
	oneByte := make([]byte, 1)
	ct := encryptor(oneByte)
	baseSize := len(ct)
	blockSize := -1

	for i := 2; i < 1000; i++ {
		pt := make([]byte, i)
		ct = encryptor(pt)
		size1 := len(ct)
		if size1 > baseSize {
			for j := i + 1; j < 1000; j++ {
				pt = make([]byte, j)
				ct = encryptor(pt)
				size2 := len(ct)
				if size2 > size1 {
					return j - i
				}
			}
		}
	}

	// should error if blockSize is negative
	return blockSize
}

func PaddedBuffer(l int) bytes.Buffer {
	var buffer bytes.Buffer

	for i := 0; i < l; i++ {
		buffer.WriteString("a")
	}

	return buffer
}

func ChosenPlainTextDictionary(padding []byte, encryptor oracle) map[[16]byte]byte {
	dict := make(map[[16]byte]byte)
	pt := make([]byte, len(padding)+1)
	copy(pt, padding)

	for i := 0; i < 256; i++ {
		pt[len(padding)] = byte(i)
		ct := encryptor(pt)

		var ctFirstBlock [16]byte
		for j := 0; j < 16; j++ {
			ctFirstBlock[j] = ct[j]
		}

		dict[ctFirstBlock] = byte(i)
	}

	return dict
}

func NextByte(known []byte, blockSize int, encryptor oracle) byte {
	var paddingAdjustment int
	paddingAdjustment = len(known) % blockSize
	padding := PaddedBuffer(blockSize - 1 - paddingAdjustment)

	untrimmedPayload := append(padding.Bytes(), known...)
	payload := untrimmedPayload[len(untrimmedPayload)-blockSize+1 : len(untrimmedPayload)]

	dict := ChosenPlainTextDictionary(payload, encryptor)

	ct := encryptor(padding.Bytes())
	targetBlock := len(known) / blockSize

	var ctTargetBlock [16]byte
	for i := 0; i < blockSize; i++ {
		ctTargetBlock[i] = ct[(targetBlock*blockSize)+i]
	}

	return dict[ctTargetBlock]
}

func DecryptTarget(encryptor oracle, targetLength int) []byte {
	known := make([]byte, 0, targetLength)

	mode := EncryptionModeDetector(encryptor)
	if mode != ECB {
		return nil
	}

	blockSize := DiscoverBlockSizeOfEncryptionOracle(encryptor)
	for i := 0; i < targetLength; i++ {
		next := NextByte(known, blockSize, encryptor)
		currentLength := len(known)
		known = known[0 : currentLength+1]
		known[currentLength] = next
	}

	return known
}
