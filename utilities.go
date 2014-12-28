package matasano

import (
	"bytes"
	"crypto/aes"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
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
	// TODO: gross that we use strings here, but we need something comparable to
	// make a hashmap.  WCDB.
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
