package matasano

import (
	"bufio"
	"bytes"
	cryptorand "crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"errors"
	mathrand "math/rand"
	"os"
	"strconv"
	"strings"
	"time"
)

type oracle func(pt []byte) (ct []byte)

// EncryptionOracleCoinToss takes a byte array as input, pads the begginning and
// end with 5-10 random bytes (on each side), and encrypts under AES.  The mode
// is randomly chosen between ECB and CBC.  If CBC mode is used, a random IV is
// used.
func EncryptionOracleCoinToss(pt []byte) ([]byte, error) {
	var ct []byte
	var encryptError error
	key := make([]byte, 16)
	cryptorand.Read(key)

	pt = PadWithRandomBytes(pt, 5, 10)

	blockCipherMode := mathrand.Intn(2)
	if blockCipherMode == ECB {
		ct, encryptError = EcbEncrypt(key, pt)
	} else {
		iv := make([]byte, 16)
		cryptorand.Read(iv)
		ct, encryptError = CbcEncrypt(key, iv, pt)
	}

	if encryptError != nil {
		return nil, encryptError
	}

	return ct, nil
}

// PadWithRandomBytes takes a byte array, and min/max ints.  It then prepends
// and appends the input with a random number (in [min, max]) of random bytes.
// The number of bytes prepended and appended are chosen separately.
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

// OracleEncryptionModeDetector returns the cipher block mode used by the oracle
// passed as an argument.  The only guessed modes are ECB and CBC.
func OracleEncryptionModeDetector(encryptor oracle) int {
	pt := make([]byte, 64)
	ct := encryptor(pt)

	return EncryptionModeDetector(ct)
}

// EncryptionModeDetector takes a byte array of ciphertext as input, attempts to
// guess the block cipher mode used (ECB or CBC), and returns the appropriate
// mode flag.
//
// The implementation is simple: it looks for a repeated block of ciphertext. If
// it sees one, it assumes the ciphertext was encrypted under ECB.  Otherwise,
// it assumes CBC was used.
func EncryptionModeDetector(ct []byte) int {
	if HasRepeatedBlock(ct, 16) {
		return ECB
	}

	return CBC
}

const fixedKeyString = "b80b215a9d87206e3fb1d40baf255a81"
const targetB64PlainText = "Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRv" +
	"d24gc28gbXkgaGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBv" +
	"biBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvIHNheSBoaQpEaWQg" +
	"eW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK"
const prefixB64PlainText = "qUIxzVDdZPWIIcmTwuZ4Y15qrzwK"

// ByteAtATimeECBEncryptor is an implementation of the oracle described at
// http://cryptopals.com/sets/2/challenges/12/
func ByteAtATimeECBEncryptor(pt []byte) []byte {
	key, _ := hex.DecodeString(fixedKeyString)
	targetBytes, _ := base64.StdEncoding.DecodeString(targetB64PlainText)
	ct, _ := EcbEncrypt(key, append(pt, targetBytes...))

	return ct
}

// ByteAtATimeECBEncryptorTricky is an implementation of the oracle described at
// http://cryptopals.com/sets/2/challenges/14
func ByteAtATimeECBEncryptorTricky(pt []byte) []byte {
	key, _ := hex.DecodeString(fixedKeyString)
	targetBytes, _ := base64.StdEncoding.DecodeString(targetB64PlainText)
	// throw in a fixed randomly-generated string to make life harder
	prependBytes, _ := base64.StdEncoding.DecodeString(prefixB64PlainText)
	ct, _ := EcbEncrypt(key, append(prependBytes, append(pt, targetBytes...)...))

	return ct
}

// DiscoverBlockSizeOfEncryptionOracle retunrs the block-size of the encryption
// oracle passed as input.  It does this by passing increasingly longer
// plaintexts to the oracle, and observes when the length of the resulting
// ciphertext increases.
//
// N.B.: this assumes the block-size of the oracle isn't that large (note the
// value of 1000 used in the for-loops below.)
func DiscoverBlockSizeOfEncryptionOracle(encryptor oracle) int {
	oneByte := make([]byte, 1)
	ct := encryptor(oneByte)
	baseSize := len(ct)

	// TODO: get rid of the hard-coded upper-limit in this for-loops.
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

	// TODO: make this an error
	return -1
}

// PaddedBuffer takes an int as input, and returns a buffer of that length full
// of "a".
func PaddedBuffer(l int) bytes.Buffer {
	var buffer bytes.Buffer

	for i := 0; i < l; i++ {
		buffer.WriteString("a")
	}

	return buffer
}

func getDictionaryForNextByte(encryptor oracle, prefixLength int, known []byte) map[[16]byte]byte {
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

// NextByte takes an encryption oracle, length of prefix prepended to attacker
// controlled plaintext, and byte array of known plaintext, and returns the
// next byte of the plaintext under attack.  It is assumed that the oracle uses
// a block cipher in ECB mode.
func NextByte(encryptor oracle, prefixLength int, known []byte) byte {
	dict := getDictionaryForNextByte(encryptor, prefixLength, known)

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

// DecryptTarget takes an encryption oracle, prefix byte array, and length of
// the target plaintext, and returns a byte array of the target plaintext. This
// implements the attack described at http://cryptopals.com/sets/2/challenges/12
// and http://cryptopals.com/sets/2/challenges/14.  An underlying assumption is
// that the encryption oracle uses a block cipher in ECB mode.
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

// User is an object used for http://cryptopals.com/sets/2/challenges/13/.
type User struct {
	email, role string
	uid         int
}

// Encode returns a string representation of a User.  It's essentially just a
// URI param string.
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

func userFromParams(params string) User {
	kvMap := parseParamString(params)
	uid, _ := strconv.Atoi(kvMap["uid"])
	return User{kvMap["email"], kvMap["role"], uid}
}

func profileFor(email string) string {
	// Don't allow metacharacters in email
	cleaned := strings.Replace(email, "=", "", -1)
	cleaned = strings.Replace(cleaned, "&", "", -1)

	u := User{cleaned, "user", 10}
	return u.Encode()
}

// GenericEncryptionOracle is an oracle that uses encrypts plaintext under ECB
// using the key GenericEncryptionOracle.
func GenericEncryptionOracle(pt []byte) []byte {
	key, _ := hex.DecodeString(fixedKeyString)
	ct, _ := EcbEncrypt(key, pt)
	return ct
}

// DecryptAndParseProfile takes ciphertext representing an encrypted user
// profile, decrypts it, parses the plaintext, and returns the corresponding
// User object.
func DecryptAndParseProfile(ct []byte) (User, error) {
	key, decodeError := hex.DecodeString(fixedKeyString)
	if decodeError != nil {
		return User{"", "", 0}, decodeError
	}

	pt, encryptError := EcbDecrypt(key, ct)
	if encryptError != nil {
		return User{"", "", 0}, encryptError
	}

	paramString := string(pt[:])
	return userFromParams(paramString), nil
}

func createEncryptedProfile(email string) []byte {
	encodedProfile := profileFor(email)
	return GenericEncryptionOracle([]byte(encodedProfile))
}

// CreateAdminProfileCipherText performs the ecb cut-and-paste attack described
// at http://cryptopals.com/sets/2/challenges/13/ to generate ciphertext that
// will decrypt to a User profile with the admin role, without any knowledge of
//the key being used to generate the ciphertext.
func CreateAdminProfileCipherText() []byte {
	email1 := "neal@neal.admin"
	profile1 := createEncryptedProfile(email1)
	adminBlock := profile1[16:32] // decrypts to "admin&uid=10&rol"
	endBlock := profile1[0:16]    // decrypts to "email=neal@neal."

	email2 := "neal@neal.com"
	profile2 := createEncryptedProfile(email2)
	firstBlock := profile2[0:32] // decrypts to "email=neal@neal.com&uid=10&role="

	return append(firstBlock, append(adminBlock, endBlock...)...)
}

// StripPKCS7Padding takes a byte array as input, strips off PKCS7 padding
// (see https://en.wikipedia.org/wiki/Padding_%28cryptography%29#PKCS7),
// and returns the result.  If the input does not have valid PKCS7 padding, an
// error is returned.
func StripPKCS7Padding(input []byte) ([]byte, error) {
	if validPKCS7Padding(input) {
		return input[0 : len(input)-int(input[len(input)-1])], nil
	}

	return nil, errors.New("Invalid PKCS7 padding!")
}

const cbcBitFlipKey = "d93a79a26b07260aadd624813e9f113d"

func cbcBitFlipStringEncryptor(pt string) ([]byte, []byte) {
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

	ct, _ := CbcEncrypt(key, iv, padded)

	return ct, iv
}

// ForgeAdminCiphertext performs the cbc bit-flipping attack described at
// http://cryptopals.com/sets/2/challenges/16/ to generate ciphertext that will
// decrypt and parse to a User with the admin role, without any knowledge of the
// key used to generate the ciphertext.  Returns the ciphertext and iv.
func ForgeAdminCiphertext() ([]byte, []byte) {
	inputString := "hackdxadminxtrue"
	targetString := "hackd;admin=true"
	ct, iv := cbcBitFlipStringEncryptor(inputString)

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

const paddingOracleKeyString = "393521e9dad8b145c200559fb6b4a960"

func getLinesFromFile(filePath string) ([]string, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return nil, err
	}

	defer file.Close()

	var lines []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		lines = append(lines, scanner.Text())
	}

	return lines, nil
}

// PaddingOracleEncryptRandomPlaintext chooses a piece of plaintext at random
// from paddingOraclePlaintexts.txt, b64 decodes it, encrypts it under
// paddingOracleKey with a random IV, and returns the IV and resulting
// ciphertext.
func PaddingOracleEncryptRandomPlaintext() ([]byte, []byte, error) {
	plaintexts, err := getLinesFromFile("paddingOraclePlaintexts.txt")
	if err != nil {
		return nil, nil, err
	}

	mathrand.Seed(time.Now().Unix()) // okay that this isn't a CSPRNG
	ptBase64 := plaintexts[mathrand.Intn(len(plaintexts))]
	unpaddedPt, _ := base64.StdEncoding.DecodeString(ptBase64)
	paddedPt := PKCS7Pad(unpaddedPt, 16*(len(unpaddedPt)/16+1))

	iv := make([]byte, 16)
	cryptorand.Read(iv)

	keyBytes, _ := hex.DecodeString(paddingOracleKeyString)
	ct, encryptError := CbcEncrypt(keyBytes, iv, paddedPt)
	if encryptError != nil {
		return nil, nil, encryptError
	}

	return iv, ct, nil
}

// CiphertextHasValidPadding takes byte arrays for an iv and ciphertext,
// decrypts the ciphertext under cbc mode with paddingOracleKeyString, and
// returns whether or not the underlying plaintext has valid PKCS7 padding.
// In the event of a decryption error, false is returned, along with the error.
func CiphertextHasValidPadding(iv, ct []byte) (bool, error) {
	keyBytes, _ := hex.DecodeString(paddingOracleKeyString)
	pt, decryptError := CbcDecrypt(keyBytes, iv, ct)
	if decryptError != nil {
		return false, decryptError
	}

	return validPKCS7Padding(pt), nil
}

func validPKCS7Padding(input []byte) bool {
	if len(input) == 0 {
		return false
	}

	lastByte := input[len(input)-1]
	if lastByte == 0 {
		return false
	}
	for i := 0; byte(i) < lastByte; i++ {
		if input[len(input)-1-int(i)] != lastByte {
			return false
		}
	}

	return true
}

func paddingOracleAttackSingleBlock(iv, block []byte) ([]byte, error) {
	if len(block) != 16 {
		return nil, errors.New("input block must be 16 bytes long")
	}
	if len(iv) != 16 {
		return nil, errors.New("iv must be 16 bytes long")
	}

	tamperIv := make([]byte, 16)
	pt := make([]byte, 16)

	for targetIndex := 15; targetIndex >= 0; targetIndex-- {
		paddingByte := byte(16 - targetIndex)

		for i := targetIndex + 1; i < 16; i++ {
			tamperIv[i] = iv[i] ^ pt[i] ^ paddingByte
		}

		for tamper := 0; tamper < 256; tamper++ {
			tamperIv[targetIndex] = byte(tamper)
			validPadding, decryptError := CiphertextHasValidPadding(tamperIv, block)

			if decryptError != nil {
				return nil, decryptError
			}

			if validPadding {
				pt[targetIndex] = iv[targetIndex] ^ paddingByte ^ byte(tamper)
				break
			} else if tamper == 255 {
				return nil, errors.New("unable to produce valid padding")
			}
		}
	}

	return pt, nil
}

// PaddingOracleAttack performs the attack described at
// http://cryptopals.com/sets/3/challenges/17/.  It takes the target iv and
// ciphertext as input, and returns the underlying plaintext.
func PaddingOracleAttack(iv, ct []byte) ([]byte, error) {
	blocks := SplitIntoBlocks(ct, 16)
	ptBlocks := make([][]byte, len(blocks))
	var err error
	var ptBlock []byte
	for index, element := range blocks {
		if index == 0 {
			ptBlock, err = paddingOracleAttackSingleBlock(iv, element)
		} else {
			ptBlock, err = paddingOracleAttackSingleBlock(blocks[index-1], element)
		}

		if err != nil {
			return nil, err
		}
		ptBlocks[index] = ptBlock
	}

	return bytes.Join(ptBlocks, nil), nil
}
