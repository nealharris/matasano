package matasano

import (
	"bytes"
	cryptorand "crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"errors"
	mathrand "math/rand"
	"strconv"
	"strings"
	"time"
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
func OracleEncryptionModeDetector(encryptor oracle) int {
	pt := make([]byte, 64)
	ct := encryptor(pt)

	return EncryptionModeDetector(ct)
}

func EncryptionModeDetector(ct []byte) int {
	guessedMode := CBC

	blocks := SplitIntoBlocks(ct, 16)
	for i := 0; i < len(blocks) && guessedMode == CBC; i++ {
		for j := 0; j < i && guessedMode == CBC; j++ {
			if bytes.Compare(blocks[i], blocks[j]) == 0 {
				guessedMode = ECB
			}
		}
	}

	return guessedMode
}

const fixedKeyString = "b80b215a9d87206e3fb1d40baf255a81"
const targetB64PlainText = "Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRv" +
	"d24gc28gbXkgaGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBv" +
	"biBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvIHNheSBoaQpEaWQg" +
	"eW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK"
const prefixB64PlainText = "qUIxzVDdZPWIIcmTwuZ4Y15qrzwK"

func ByteAtATimeECBEncryptor(pt []byte) []byte {
	key, _ := hex.DecodeString(fixedKeyString)
	targetBytes, _ := base64.StdEncoding.DecodeString(targetB64PlainText)

	return EcbEncrypt(key, append(pt, targetBytes...))
}

func ByteAtATimeECBEncryptorTricky(pt []byte) []byte {
	key, _ := hex.DecodeString(fixedKeyString)
	targetBytes, _ := base64.StdEncoding.DecodeString(targetB64PlainText)
	// throw in a fixed randomly-generated string to make life harder
	prependBytes, _ := base64.StdEncoding.DecodeString(prefixB64PlainText)

	return EcbEncrypt(key, append(prependBytes, append(pt, targetBytes...)...))
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

func GetDictionaryForNextByte(encryptor oracle, prefixLength int, known []byte) map[[16]byte]byte {
	paddingLength := ((16 - 1) - prefixLength - len(known)) % 16
	if paddingLength < 0 {
		paddingLength += 16
	}

	padding := PaddedBuffer(paddingLength)
	shortPayload := append(padding.Bytes(), known...)
	payload := make([]byte, len(shortPayload)+1)
	copy(payload, shortPayload)

	targetBlock := (prefixLength + len(payload)) / 16

	dict := make(map[[16]byte]byte)
	for i := 0; i < 256; i++ {
		payload[len(payload)-1] = byte(i)
		ct := encryptor(payload)

		var targetCtBlock [16]byte
		for j := 0; j < 16; j++ {
			targetCtBlock[j] = ct[16*(targetBlock-1)+j]
		}

		dict[targetCtBlock] = byte(i)
	}

	return dict
}

func NextByte(encryptor oracle, prefixLength int, known []byte) byte {
	dict := GetDictionaryForNextByte(encryptor, prefixLength, known)

	paddingLength := ((16 - 1) - len(known) - prefixLength) % 16
	if paddingLength < 0 {
		paddingLength += 16
	}
	payload := PaddedBuffer(paddingLength)

	ct := encryptor(payload.Bytes())
	targetBlockOffset := (prefixLength + len(payload.Bytes()) + len(known)) / 16

	var ctTargetBlock [16]byte
	for i := 0; i < 16; i++ {
		ctTargetBlock[i] = ct[16*(targetBlockOffset)+i]
	}

	return dict[ctTargetBlock]
}

func DecryptTarget(encryptor oracle, prefix []byte, targetLength int) []byte {
	known := make([]byte, 0, targetLength)

	mode := OracleEncryptionModeDetector(encryptor)
	if mode != ECB {
		return nil
	}

	blockSize := DiscoverBlockSizeOfEncryptionOracle(encryptor)
	if blockSize != 16 {
		return nil
	}

	for i := 0; i < targetLength; i++ {
		next := NextByte(encryptor, len(prefix), known)
		currentLength := len(known)
		known = known[0 : currentLength+1]
		known[currentLength] = next
	}

	return known
}

type User struct {
	email, role string
	uid         int
}

func (u User) Encode() string {
	return "email=" + u.email + "&uid=" + strconv.Itoa(u.uid) + "&role=" + u.role
}

func parseParamString(params string) map[string]string {
	kvMap := make(map[string]string)
	var tokens []string

	kvPairs := strings.Split(params, "&")
	for _, kvPair := range kvPairs {
		tokens = strings.Split(kvPair, "=")
		kvMap[tokens[0]] = tokens[1]
	}

	return kvMap
}

func UserFromParams(params string) User {
	kvMap := parseParamString(params)
	uid, _ := strconv.Atoi(kvMap["uid"])
	return User{kvMap["email"], kvMap["role"], uid}
}

func ProfileFor(email string) string {
	// Don't allow metacharacters in email
	cleaned := strings.Replace(email, "=", "", -1)
	cleaned = strings.Replace(cleaned, "&", "", -1)

	u := User{cleaned, "user", 10}
	return u.Encode()
}

func GenericEncryptionOracle(pt []byte) []byte {
	key, _ := hex.DecodeString(fixedKeyString)
	return EcbEncrypt(key, pt)
}

func DecryptAndParseProfile(ct []byte) User {
	key, _ := hex.DecodeString(fixedKeyString)
	pt := EcbDecrypt(key, ct)

	paramString := string(pt[:])
	return UserFromParams(paramString)
}

func CreateEncryptedProfile(email string) []byte {
	encodedProfile := ProfileFor(email)
	return GenericEncryptionOracle([]byte(encodedProfile))
}

// Uses CreateEncryptedProfile as an oracle for generating ciphertext.
// Plaintext can't contain '=' or '&', since those get stripped by the encoder.
func GetMetacharacterFreeCipherText(pt string) []byte {
	prePadding := "foobarbazz" // len("email=foobarbazz") == 16
	paddedPt := string(PKCS7Pad([]byte(pt), 16))

	encryptedProfile := CreateEncryptedProfile(prePadding + paddedPt)
	// How many blocks of ciphertext do we need?
	numBlocks := (len(paddedPt)) / 16
	return encryptedProfile[16 : 16+16*(numBlocks)]
}

func CreateAdminProfileCipherText() []byte {
	email1 := "neal@neal.admin"
	profile1 := CreateEncryptedProfile(email1)
	adminBlock := profile1[16:32] // decrypts to "admin&uid=10&rol"
	endBlock := profile1[0:16]    // decrypts to "email=neal@neal."

	email2 := "neal@neal.com"
	profile2 := CreateEncryptedProfile(email2)
	firstBlock := profile2[0:32] // decrypts to "email=neal@neal.com&uid=10&role="

	return append(firstBlock, append(adminBlock, endBlock...)...)
}

func StripPKCS7Padding(input []byte) ([]byte, error) {
	lastByte := input[len(input)-1]
	var i byte
	for i = 0; i < lastByte; i++ {
		if input[len(input)-1-int(i)] != lastByte {
			return nil, errors.New("Invalid PKCS7 padding!")
		}
	}

	return input[0 : len(input)-int(lastByte)], nil
}

const cbcBitFlipKey = "d93a79a26b07260aadd624813e9f113d"

func CbcBitFlipStringEncryptor(pt string) ([]byte, []byte) {
	// first, kill all ';' and '=' from the input
	cleaned := strings.Replace(pt, ";", "", -1)
	cleaned = strings.Replace(cleaned, "=", "", -1)

	prefix := "comment1=cooking%20MCs;userdata="
	suffix := ";comment2=%20like%20a%20pound%20of%20bacon"
	bytes := []byte(prefix + cleaned + suffix)

	lengthWithPadding := (len(bytes)/16 + 1) * 16
	padded := PKCS7Pad(bytes, lengthWithPadding)

	key, _ := hex.DecodeString(cbcBitFlipKey)
	iv := make([]byte, 16)
	cryptorand.Read(iv)

	return CbcEncrypt(key, padded, iv), iv
}

func CbcBitFlipIsAdmin(ct, iv []byte) (bool, error) {
	keyBytes, _ := hex.DecodeString(cbcBitFlipKey)
	pt := CbcDecrypt(keyBytes, ct, iv)
	stripped, err := StripPKCS7Padding(pt)

	if err != nil {
		return false, err
	}

	return strings.Contains(string(stripped), ";admin=true;"), nil
}

func ForgeAdminCiphertext() ([]byte, []byte) {
	inputString := "hackdxadminxtrue"
	targetString := "hackd;admin=true"
	ct, iv := CbcBitFlipStringEncryptor(inputString)

	tamperedCt := make([]byte, len(ct))
	copy(tamperedCt, ct)

	// target is in third block of ct
	// need to xor 2nd block of ct with hackdxadminxtrue XOR hackd;admin=true
	tamperMask, _ := Xor([]byte(inputString), []byte(targetString))
	secondBlock := tamperedCt[16:32]
	replacement, _ := Xor(tamperMask, secondBlock)

	for i := 0; i < 16; i++ {
		tamperedCt[i+16] = replacement[i]
	}

	return tamperedCt, iv
}
