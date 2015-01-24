package matasano

import (
	"bytes"
	"crypto/aes"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io/ioutil"
)

// ReadB64File takes the path to a file of base64 encoded data, reads the file
// at that path, base64 decodes the data, and returns the resulting []byte.
func ReadB64File(filePath string) ([]byte, error) {
	e64 := base64.StdEncoding

	encoded, readErr := ioutil.ReadFile(filePath)
	if readErr != nil {
		return nil, readErr
	}

	maxDecodedLen := e64.DecodedLen(len(encoded))
	decoded := make([]byte, maxDecodedLen)
	numBytes, decodeErr := e64.Decode(decoded, encoded)
	if decodeErr != nil {
		return nil, decodeErr
	}

	return decoded[0:numBytes], nil
}

// HexToB64 takes a string, hex-decodes it, encodes the result in base64, and
// returns the result.  Returns an error if unable to hex-decode the input.
func HexToB64(s string) (string, error) {
	bytes, err := hex.DecodeString(s)
	if err != nil {
		fmt.Println("error decoding hex: ", err)
		return "", err
	}
	return base64.StdEncoding.EncodeToString(bytes), nil
}

// B64ToHex takes a string, base64-decodes it, encodes the result in hex, and
// returns the result.  Returns an error if unable to base64-decode the input.
func B64ToHex(s string) (string, error) {
	bytes, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		fmt.Println("error: ", err)
		return "", err
	}
	return hex.EncodeToString(bytes), nil
}

// Xor takes two byte arrays of the same length, computes the compentwise xor
// of the inputs, and returns the resulting array.  Returns an error if the
// input arrays are not the same length.
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

// SingleCharXor takes a byte and byte array as input, xors the byte against
// each element of the byte array, and returns the result.
func SingleCharXor(b byte, s []byte) ([]byte, error) {
	repeated := bytes.Repeat([]byte{b}, len(s))
	return Xor(repeated, s)
}

// ExtendByteArray takes a byte array, and an integer-valued length, extends the
// byte array to the length passed in, and returns the result.  For example:
// ExtendByteArray([]byte{1,2,3}, 8) == {1,2,3,1,2,3,1,2}.
func ExtendByteArray(b []byte, length int) []byte {
	currentLength := len(b)
	extended := bytes.Repeat(b, length/currentLength)
	return append(extended, b[0:length%currentLength]...)
}

// RepeatingKeyXor takes key and plaintext (both []byte), xors the key against
// the plaintext (extending the key as necessary), and returns the result. For
// example, RepeatingKeyXor([]byte{1,2}, []byte{1,2,0}) == []byte{0,0,1}.
func RepeatingKeyXor(key, plaintext []byte) []byte {
	extendedKey := ExtendByteArray(key, len(plaintext))
	result, _ := Xor(extendedKey, plaintext)
	return result
}

// BreakRepeatingKeyXor takes a []byte array of ciphertext as input.  Assuming
// that ciphertext was encrypted with 'repeating-key xor', this performs the
// attack described at http://cryptopals.com/sets/1/challenges/6/,
// and returns the plaintext.
func BreakRepeatingKeyXor(ciphertext []byte) ([]byte, error) {
	keyLength, err := repeatingKeyXorKeyLength(ciphertext, 2, 40)
	if err != nil {
		return nil, err
	}

	transposed := transpose(ciphertext, keyLength)

	key := make([]byte, len(transposed))
	for index, element := range transposed {
		key[index] = FindSingleCharForXor(element)
	}

	return RepeatingKeyXor(key, ciphertext), nil
}

func repeatingKeyXorKeyLength(ciphertext []byte, minKeyLength, maxKeyLength int) (int, error) {
	bestWeight := -1.0
	bestKeyLength := 0

	for kl := minKeyLength; kl <= maxKeyLength; kl++ {
		currWeight := 0.0

		for i := 0; i < 4; i++ {
			for j := i + 1; j < 4; j++ {
				dist, err := normalizedHammingDistance(ciphertext[i*kl:(i+1)*kl],
					ciphertext[j*kl:(j+1)*kl])
				if err != nil {
					return -1, err
				}

				currWeight += dist
			}
		}

		if currWeight < bestWeight || bestWeight < 0 {
			bestWeight = currWeight
			bestKeyLength = kl
		}
	}

	return bestKeyLength, nil
}

func normalizedHammingDistance(b1, b2 []byte) (float64, error) {
	dist, err := HammingDistance(b1, b2)
	return float64(dist) / float64(len(b1)), err
}

func transpose(input []byte, length int) [][]byte {
	numBlocks := len(input) / length
	if numBlocks%length != 0 {
		numBlocks++
	}

	transposed := make([][]byte, length)
	for i := range transposed {
		transposed[i] = make([]byte, numBlocks)
	}

	for i := 0; i < len(input); i++ {
		colIndex := i % length
		rowIndex := i / length
		transposed[colIndex][rowIndex] = input[i]
	}

	return transposed
}

// HammingDistance takes two byte arrays as input, and returns their Hamming
// Distance (https://en.wikipedia.org/wiki/Hamming_distance).  Returns an error
// if the byte arrays are not the same length.
func HammingDistance(b1, b2 []byte) (int, error) {
	if len(b1) != len(b2) {
		return 0, errors.New("cannot xor byte arrays of different lengths")
	}

	hd := 0
	for i := 0; i < len(b1); i++ {
		for xor := b1[i] ^ b2[i]; xor != 0; xor = xor >> 1 {
			if xor&1 != 0 {
				hd++
			}
		}
	}

	return hd, nil
}

// EcbDecrypt takes byte arrays for key and ciphertext, decrypts the ciphertext
// with the key using AES in ecb mode, and returns the resulting plaintext.
// The key-length must be either 16, 24, or 32 bytes in length; otherwise an
// error will be returned.
func EcbDecrypt(key, ct []byte) ([]byte, error) {
	cipher, keyError := aes.NewCipher(key)
	if keyError != nil {
		return nil, keyError
	}
	numBlocks := len(ct) / 16
	pt := make([]byte, len(ct))

	for i := 0; i < numBlocks; i++ {
		cipher.Decrypt(pt[16*i:16*(i+1)], ct[16*i:16*(i+1)])
	}

	return pt, nil
}

// EcbEncrypt takes byte arrays for key and plaintext, encrypts the plaintext
// with the key using AES in ecb mode, and returns the resulting ciphertext.
// The key-length must be either 16, 24, or 32 bytes in length; otherwise an
// error will be returned.
func EcbEncrypt(key, pt []byte) ([]byte, error) {
	cipher, keyError := aes.NewCipher(key)
	if keyError != nil {
		return nil, keyError
	}

	blockSize := 16
	numBlocks := len(pt) / blockSize
	if len(pt)%blockSize != 0 {
		numBlocks++
	}
	paddedPt := make([]byte, blockSize*numBlocks)
	copy(paddedPt, pt)

	ct := make([]byte, blockSize*numBlocks)
	for i := 0; i < numBlocks; i++ {
		cipher.Encrypt(ct[blockSize*i:blockSize*(i+1)], paddedPt[blockSize*i:blockSize*(i+1)])
	}

	return ct, nil
}

// HasRepeatedBlock takes a byte array and blockSize int, and returns true or
// false, depending on whether the byte array contains duplicate blocks after
// splitting it into blocks of size blockSize.
func HasRepeatedBlock(ct []byte, blockSize int) bool {
	blocks := SplitIntoBlocks(ct, blockSize)
	// TODO: gross that we use strings here, but we need something comparable to
	// make a hashmap.  WCDB.
	set := make(map[string]bool)
	for _, block := range blocks {
		key := string(block)
		if set[key] {
			return true
		}
		set[key] = true
	}

	return false
}

// SplitIntoBlocks takes a byte array and blockSize, and returns an array of
// byte arrays, all of length blockSize.  If the length of the byte array is not
// a multiple of blockSize, then the last block of the result will be padded
// with 0.
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
			}
			res[i][j] = b[i*blockSize+j]
		}
	}

	return res
}

// PKCS7Pad takes a byte array and size (int) as input, pads the byte array to
// length size with PKCS7 padding
// (https://en.wikipedia.org/wiki/Padding_%28cryptography%29#PKCS7)
// and returns the result.
func PKCS7Pad(b []byte, size int) []byte {
	padding := size - len(b)

	result := make([]byte, size)
	copy(result, b)

	for i := len(b); i < len(result); i++ {
		result[i] = byte(padding)
	}

	return result
}

// CbcEncrypt takes byte arrays for key, iv, plaintext,
// encrypts the plaintext with the key using AES in cbc mode, and returns the
// resulting ciphertext. The key-length must be either 16, 24, or 32 bytes in
// length; otherwise an error will be returned.  Note that the iv is not
// returned as part of the ciphertext.
func CbcEncrypt(key, iv, pt []byte) ([]byte, error) {
	cipher, keyError := aes.NewCipher(key)
	if keyError != nil {
		return nil, keyError
	}

	numBlocks := len(pt) / 16
	if len(pt)%16 != 0 {
		numBlocks++
	}
	ct := make([]byte, numBlocks*16)
	paddedPt := make([]byte, numBlocks*16)
	copy(paddedPt, pt)

	nextXor := iv

	var xored []byte
	for i := 0; i < numBlocks; i++ {
		xored, _ = Xor(nextXor, paddedPt[16*i:16*(i+1)])
		cipher.Encrypt(ct[16*i:16*(i+1)], xored)
		nextXor = ct[16*i : 16*(i+1)]
	}

	return ct, nil
}

// CbcDecrypt takes byte arrays for key, iv, and ciphertext,
// decrypts the plaintext with the key using AES in cbc mode, and returns the
// resulting ciphertext. The key-length must be either 16, 24, or 32 bytes in
// length; otherwise an error will be returned.  Note that the iv is taken as
// a separate argument from the ciphertext.
func CbcDecrypt(key, iv, ct []byte) ([]byte, error) {
	cipher, keyError := aes.NewCipher(key)
	if keyError != nil {
		return nil, keyError
	}

	numBlocks := len(ct) / 16
	if len(ct)%16 != 0 {
		numBlocks++
	}
	pt := make([]byte, numBlocks*16)

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

	return pt, nil
}

// CtrEncrypt implements AES-CTR mode.  It takes the key and plaintext as byte
// arrays, the nonce as a uint, and returns a byte array for the resulting
// plaintext.
func (enc *CtrEncryptor) CtrEncrypt(pt []byte) ([]byte, error) {
	numPtBlocks := len(pt) / 16
	if len(pt)%16 != 0 {
		numPtBlocks++
	}

	keyStream := make([]byte, numPtBlocks*16)

	for i := 0; i < numPtBlocks; i++ {
		keyStreamBlock, ctrErr := enc.ctrKeystreamForBlock(uint64(i))
		if ctrErr != nil {
			return nil, ctrErr
		}

		for j := 0; j < 16; j++ {
			keyStream[i*16+j] = keyStreamBlock[j]
		}
	}

	ct, xorError := Xor(pt, keyStream[0:len(pt)])
	if xorError != nil {
		return nil, xorError
	}

	return ct, nil
}

func (enc *CtrEncryptor) ctrKeystreamForBlock(blockIndex uint64) ([]byte, error) {
	littleEndianNonce := make([]byte, 8)
	binary.LittleEndian.PutUint64(littleEndianNonce, enc.nonce)

	littleEndianCounter := make([]byte, 8)
	binary.LittleEndian.PutUint64(littleEndianCounter, blockIndex)

	preKeyStream := make([]byte, 16)
	preKeyStream = append(littleEndianNonce, littleEndianCounter...)

	cipher, keyError := aes.NewCipher(enc.key)
	if keyError != nil {
		return nil, keyError
	}

	keyStreamBlock := make([]byte, 16)
	cipher.Encrypt(keyStreamBlock, preKeyStream)

	return keyStreamBlock, nil
}

// CtrDecrypt is just an alias for CtrEncrypt.
func (enc *CtrEncryptor) CtrDecrypt(pt []byte) ([]byte, error) {
	return enc.CtrEncrypt(pt)
}

// Block cipher mode flags.
const (
	ECB = iota
	CBC
	CTR
)

// CtrEncryptor provides AES encryption in Ctr mode.
type CtrEncryptor struct {
	key   []byte
	nonce uint64
}

func (enc *CtrEncryptor) edit(ct []byte, offset int, newPlaintext []byte) ([]byte, error) {
	keyStream, ctrErr := enc.ctrKeystreamForBlock(uint64(offset / 16))
	if ctrErr != nil {
		return nil, ctrErr
	}

	ctBlock, xorErr := Xor(keyStream, newPlaintext)
	if xorErr != nil {
		return nil, xorErr
	}

	modifedCt := make([]byte, len(ct))
	copy(modifedCt, ct)
	for i := 0; i < 16; i++ {
		modifedCt[offset+i] = ctBlock[i]
	}

	return modifedCt, nil
}
