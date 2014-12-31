package matasano

import (
	"bytes"
	"io/ioutil"
	"testing"
)
import (
	"encoding/base64"
	"encoding/hex"
)

const hexTestString = "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d"
const b64TestString = "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t"

func TestHexToB64(t *testing.T) {
	result, err := HexToB64(hexTestString)

	if err != nil {
		t.Errorf("got unexpected error: %v", err)
	}

	if result != b64TestString {
		t.Errorf("Expected %v, but got %v", b64TestString, result)
	}
}

func TestB64ToHex(t *testing.T) {
	result, err := B64ToHex(b64TestString)

	if err != nil {
		t.Errorf("got unexpected error: %v", err)
	}

	if result != hexTestString {
		t.Errorf("Expected %v, but got %v", hexTestString, result)
	}
}

func TestXor(t *testing.T) {
	s1 := "1c0111001f010100061a024b53535009181c"
	b1, _ := hex.DecodeString(s1)
	s2 := "686974207468652062756c6c277320657965"
	b2, _ := hex.DecodeString(s2)
	expectedString := "746865206b696420646f6e277420706c6179"
	expectedBytes, _ := hex.DecodeString(expectedString)

	result, err := Xor(b1, b2)

	if err != nil {
		t.Errorf("got unexpected error: %v", err)
	}

	if bytes.Compare(result, expectedBytes) != 0 {
		t.Errorf("expected %v, but got %v", expectedBytes, result)
	}
}

func TestRepeatingKeyXor(t *testing.T) {
	key := []byte("ICE")
	input := []byte("Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal")

	resultCt := RepeatingKeyXor(key, input)
	resultCtHex := hex.EncodeToString(resultCt)

	expectedCtHex := "0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f"

	if resultCtHex != expectedCtHex {
		t.Errorf("expected %v, but got %v", expectedCtHex, resultCtHex)
	}
}

func TestHammingDistance(t *testing.T) {
	b1 := []byte("this is a test")
	b2 := []byte("wokka wokka!!!")

	dist, err := HammingDistance(b1, b2)
	expectedDistance := 37

	if err != nil {
		t.Errorf("got unexpected error: %v", err)
	}

	if expectedDistance != dist {
		t.Errorf("expected Hamming Distance of %v, but got %v", expectedDistance, dist)
	}
}

func TestHasRepeatedBlock(t *testing.T) {
	bytes := []byte{1, 2, 3, 4, 1, 2, 5, 6}
	if HasRepeatedBlock(bytes, 2) != true {
		t.Errorf("Should have found repeated block of size 2 in %v", bytes)
	}

	if HasRepeatedBlock(bytes, 4) != false {
		t.Errorf("Should not have found repeated block of size 4 in %v", bytes)
	}
}

func TestPKCS7Pad(t *testing.T) {
	unpadded := []byte{1, 1}
	padded := PKCS7Pad(unpadded, 4)
	if bytes.Compare(padded, []byte{1, 1, 2, 2}) != 0 {
		t.Errorf("Incorrect padding.  Got: %v", padded)
	}
}

// TODO: DRY up ecb/cbc tests.  LOTS of repeated code.
func TestEcbEncrypt(t *testing.T) {
	e64 := base64.StdEncoding

	encodedPtBytes, ptReadErr := ioutil.ReadFile("ecbPlaintext.txt")
	if ptReadErr != nil {
		t.Errorf("error reading pt file: %v", ptReadErr)
	}

	maxPtLen := e64.DecodedLen(len(encodedPtBytes))
	decodedPt := make([]byte, maxPtLen)
	numPtBytes, ptDecodeErr := e64.Decode(decodedPt, encodedPtBytes)
	if ptDecodeErr != nil {
		t.Errorf("error decoding plaintext: %v", ptDecodeErr)
	}

	key := []byte("YELLOW SUBMARINE")
	resultCt, encryptError := EcbEncrypt(key, decodedPt[0:numPtBytes])
	if encryptError != nil {
		t.Errorf("Error encrypting: %v", encryptError)
	}

	expectedCtEncoded, ctReadErr := ioutil.ReadFile("ecbCiphertext.txt")
	if ctReadErr != nil {
		t.Errorf("error reading ct file: %v", ctReadErr)
	}

	maxCtLen := e64.DecodedLen(len(expectedCtEncoded))
	decodedCt := make([]byte, maxCtLen)
	numCtBytes, ctDecodeErr := e64.Decode(decodedCt, expectedCtEncoded)
	if ctDecodeErr != nil {
		t.Errorf("error decoding ciphertext: %v", ctDecodeErr)
	}

	if bytes.Compare(decodedCt[0:numCtBytes], resultCt) != 0 {
		t.Errorf("expected %v, but got %v", e64.EncodeToString(decodedCt), e64.EncodeToString(resultCt))
	}
}

func TestEcbDecrypt(t *testing.T) {
	e64 := base64.StdEncoding

	ctBytes, ctReadErr := ioutil.ReadFile("ecbCiphertext.txt")
	if ctReadErr != nil {
		t.Errorf("error reading ct file: %v", ctReadErr)
	}

	maxCtLen := e64.DecodedLen(len(ctBytes))
	decodedCt := make([]byte, maxCtLen)
	numCtBytes, ctDecodeErr := e64.Decode(decodedCt, ctBytes)

	if ctDecodeErr != nil {
		t.Errorf("error decoding ciphertext: %v", ctDecodeErr)
	}

	key := []byte("YELLOW SUBMARINE")
	resultPt, _ := EcbDecrypt(key, decodedCt[0:numCtBytes])

	encodedExpectedPtBytes, ptReadErr := ioutil.ReadFile("ecbPlaintext.txt")
	if ptReadErr != nil {
		t.Errorf("error reading pt file: %v", ptReadErr)
	}

	maxPtLen := e64.DecodedLen(len(encodedExpectedPtBytes))
	decodedPt := make([]byte, maxPtLen)
	_, ptDecodeErr := e64.Decode(decodedPt, encodedExpectedPtBytes)

	if ptDecodeErr != nil {
		t.Errorf("error decoding expected plaintext: %v", ptDecodeErr)
	}

	if bytes.Compare(decodedPt, resultPt) != 0 {
		t.Errorf("expected %v, but got %v", e64.EncodeToString(decodedPt), e64.EncodeToString(resultPt))
	}
}

func TestCbcEncrypt(t *testing.T) {
	e64 := base64.StdEncoding

	ptBytes, ptReadErr := ioutil.ReadFile("cbcPlaintext.txt")
	if ptReadErr != nil {
		t.Errorf("error reading plaintext file: %v", ptReadErr)
	}

	maxPtLen := e64.DecodedLen(len(ptBytes))
	decodedPt := make([]byte, maxPtLen)
	_, ptDecodeErr := e64.Decode(decodedPt, ptBytes)

	if ptDecodeErr != nil {
		t.Errorf("error decoding plaintext: %v", ptDecodeErr)
	}

	key := []byte("YELLOW SUBMARINE")
	iv := make([]byte, 16)
	resultCt, encryptError := CbcEncrypt(key, iv, decodedPt)
	if encryptError != nil {
		t.Errorf("Error decrypting: %v", encryptError)
	}

	encodedExpectedCtBytes, ctReadErr := ioutil.ReadFile("cbcCiphertext.txt")
	if ctReadErr != nil {
		t.Errorf("error reading pt file: %v", ctReadErr)
	}

	maxCtLen := e64.DecodedLen(len(encodedExpectedCtBytes))
	decodedCt := make([]byte, maxCtLen)
	numCtBytes, ctDecodeErr := e64.Decode(decodedCt, encodedExpectedCtBytes)

	if ctDecodeErr != nil {
		t.Errorf("error decoding expected plaintext: %v", ptDecodeErr)
	}

	if bytes.Compare(decodedCt[0:numCtBytes], resultCt) != 0 {
		t.Errorf("expected %v, but got %v", e64.EncodeToString(decodedCt), e64.EncodeToString(resultCt))
	}
}

func TestCbcDecrypt(t *testing.T) {
	e64 := base64.StdEncoding

	ctBytes, ctReadErr := ioutil.ReadFile("cbcCiphertext.txt")
	if ctReadErr != nil {
		t.Errorf("error reading ct file: %v", ctReadErr)
	}

	maxCtLen := e64.DecodedLen(len(ctBytes))
	decodedCt := make([]byte, maxCtLen)
	numCtBytes, ctDecodeErr := e64.Decode(decodedCt, ctBytes)

	if ctDecodeErr != nil {
		t.Errorf("error decoding ciphertext: %v", ctDecodeErr)
	}

	key := []byte("YELLOW SUBMARINE")
	iv := make([]byte, 16)
	resultPt, decryptError := CbcDecrypt(key, iv, decodedCt[0:numCtBytes])
	if decryptError != nil {
		t.Errorf("Error decrypting: %v", decryptError)
	}

	encodedExpectedPtBytes, ptReadErr := ioutil.ReadFile("cbcPlaintext.txt")
	if ptReadErr != nil {
		t.Errorf("error reading pt file: %v", ptReadErr)
	}

	maxPtLen := e64.DecodedLen(len(encodedExpectedPtBytes))
	decodedPt := make([]byte, maxPtLen)
	_, ptDecodeErr := e64.Decode(decodedPt, encodedExpectedPtBytes)

	if ptDecodeErr != nil {
		t.Errorf("error decoding expected plaintext: %v", ptDecodeErr)
	}

	if bytes.Compare(decodedPt, resultPt) != 0 {
		t.Errorf("expected %v, but got %v", e64.EncodeToString(decodedPt), e64.EncodeToString(resultPt))
	}
}

func TestCtrEncrypt(t *testing.T) {
	e64 := base64.StdEncoding
	b64Ciphertext := "L77na/nrFsKvynd6HzOoG7GHTLXsTVu9qvY/2syLXzhPweyyMTJULu/6/kXX0KSvoOLSFQ=="
	b64ExpectedPlaintext := "WW8sIFZJUCBMZXQncyBraWNrIGl0IEljZSwgSWNlLCBiYWJ5IEljZSwgSWNlLCBiYWJ5IA=="
	keyBytes := []byte("YELLOW SUBMARINE")

	ct, ctDecodeErr := e64.DecodeString(b64Ciphertext)
	if ctDecodeErr != nil {
		t.Errorf("error decoding ciphertext: %v", ctDecodeErr)
	}

	expectedPt, expectedPtDecoderr := e64.DecodeString(b64ExpectedPlaintext)
	if expectedPtDecoderr != nil {
		t.Errorf("error decoding expected plaintext: %v", expectedPtDecoderr)
	}

	pt, decryptError := CtrEncrypt(keyBytes, ct, 0)
	if decryptError != nil {
		t.Errorf("error decrypting ciphertext: %v", decryptError)
	}

	if bytes.Compare(expectedPt, pt) != 0 {
		t.Errorf("expected %v, but got %v", expectedPt, pt)
	}
}
