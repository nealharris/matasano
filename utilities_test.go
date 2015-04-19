package matasano

import (
	"bytes"
	"math/big"
	"math/rand"
	"reflect"
	"testing"
	"time"
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
	pt, ptDecodeErr := ReadB64File("ecbPlaintext.txt")
	if ptDecodeErr != nil {
		t.Errorf("error decoding plaintext: %v", ptDecodeErr)
	}

	key := []byte("YELLOW SUBMARINE")
	resultCt, encryptError := EcbEncrypt(key, pt)
	if encryptError != nil {
		t.Errorf("Error encrypting: %v", encryptError)
	}

	expectedCt, ctDecodeErr := ReadB64File("ecbCiphertext.txt")
	if ctDecodeErr != nil {
		t.Errorf("error reading ct file: %v", ctDecodeErr)
	}

	if bytes.Compare(expectedCt, resultCt) != 0 {
		t.Errorf("expected %v, but got %v", expectedCt, resultCt)
	}
}

func TestEcbDecrypt(t *testing.T) {
	ctBytes, ctReadErr := ReadB64File("ecbCiphertext.txt")
	if ctReadErr != nil {
		t.Errorf("error reading ct file: %v", ctReadErr)
	}

	key := []byte("YELLOW SUBMARINE")
	resultPt, _ := EcbDecrypt(key, ctBytes)

	expectedPtBytes, ptReadErr := ReadB64File("ecbPlaintext.txt")
	if ptReadErr != nil {
		t.Errorf("error reading pt file: %v", ptReadErr)
	}

	if bytes.Compare(expectedPtBytes, resultPt) != 0 {
		t.Errorf("expected %v, but got %v", expectedPtBytes, resultPt)
	}
}

func TestCbcEncrypt(t *testing.T) {
	ptBytes, ptReadErr := ReadB64File("cbcPlaintext.txt")
	if ptReadErr != nil {
		t.Errorf("error reading plaintext file: %v", ptReadErr)
	}

	key := []byte("YELLOW SUBMARINE")
	iv := make([]byte, 16)
	cbcEnc := CbcEncryptor{key, iv}

	resultCt, encryptError := cbcEnc.CbcEncrypt(ptBytes)
	if encryptError != nil {
		t.Errorf("Error decrypting: %v", encryptError)
	}

	expectedCtBytes, ctReadErr := ReadB64File("cbcCiphertext.txt")
	if ctReadErr != nil {
		t.Errorf("error reading pt file: %v", ctReadErr)
	}

	if bytes.Compare(expectedCtBytes, resultCt) != 0 {
		t.Errorf("expected %v, but got %v", expectedCtBytes, resultCt)
	}
}

func TestCbcDecrypt(t *testing.T) {
	ctBytes, ctReadErr := ReadB64File("cbcCiphertext.txt")
	if ctReadErr != nil {
		t.Errorf("error reading ct file: %v", ctReadErr)
	}

	key := []byte("YELLOW SUBMARINE")
	iv := make([]byte, 16)
	cbcEnc := CbcEncryptor{key, iv}

	resultPt, decryptError := cbcEnc.CbcDecrypt(ctBytes)
	if decryptError != nil {
		t.Errorf("Error decrypting: %v", decryptError)
	}

	expectedPtBytes, ptReadErr := ReadB64File("cbcPlaintext.txt")
	if ptReadErr != nil {
		t.Errorf("error reading pt file: %v", ptReadErr)
	}

	if bytes.Compare(expectedPtBytes, resultPt) != 0 {
		t.Errorf("expected %v, but got %v", expectedPtBytes, resultPt)
	}
}

func TestCtrDecrypt(t *testing.T) {
	e64 := base64.StdEncoding
	b64Ciphertext := "L77na/nrFsKvynd6HzOoG7GHTLXsTVu9qvY/2syLXzhPweyyMTJULu/6/kXX0KSvoOLSFQ=="
	b64ExpectedPlaintext := "WW8sIFZJUCBMZXQncyBraWNrIGl0IEljZSwgSWNlLCBiYWJ5IEljZSwgSWNlLCBiYWJ5IA=="
	keyBytes := []byte("YELLOW SUBMARINE")

	ctrEnc := CtrEncryptor{keyBytes, 0}

	ct, ctDecodeErr := e64.DecodeString(b64Ciphertext)
	if ctDecodeErr != nil {
		t.Errorf("error decoding ciphertext: %v", ctDecodeErr)
	}

	expectedPt, expectedPtDecoderr := e64.DecodeString(b64ExpectedPlaintext)
	if expectedPtDecoderr != nil {
		t.Errorf("error decoding expected plaintext: %v", expectedPtDecoderr)
	}

	pt, decryptError := ctrEnc.CtrDecrypt(ct)
	if decryptError != nil {
		t.Errorf("error decrypting ciphertext: %v", decryptError)
	}

	if bytes.Compare(expectedPt, pt) != 0 {
		t.Errorf("expected %v, but got %v", expectedPt, pt)
	}
}

func TestBreakRepeatingKeyXor(t *testing.T) {
	ctBytes, ctReadErr := ReadB64File("repeatingKeyXorTest.txt")
	if ctReadErr != nil {
		t.Errorf("error reading ct file: %v", ctReadErr)
	}

	pt, err := BreakRepeatingKeyXor(ctBytes)
	if err != nil {
		t.Errorf("error while trying to recover pt: %v", err)
	}

	expectedPt, expectedPtReadErr := ReadB64File("repeatingKeyXorTestPt.txt")
	if expectedPtReadErr != nil {
		t.Errorf("error reading expected pt file: %v", expectedPtReadErr)
	}

	if bytes.Compare(expectedPt, pt) != 0 {
		t.Errorf("expected to recover %v, but got %v", expectedPt, pt)
	}
}

func TestTranspose(t *testing.T) {
	b := []byte{1, 2, 3, 4}
	transposed := transpose(b, 2)
	expected := [][]byte{{1, 3}, {2, 4}}

	if !reflect.DeepEqual(transposed, expected) {
		t.Errorf("expected %v, but got %v", expected, transposed)
	}
}

const bigP = "ffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552bb9ed529077096966d670c354e4abc9804f1746c08ca237327ffffffffffffffff"

func TestDiffieHelman(t *testing.T) {
	pBytes, decodeErr := hex.DecodeString(bigP)
	if decodeErr != nil {
		t.Errorf("error decoding bigP hex string")
	}

	p := big.NewInt(0)
	p.SetBytes(pBytes)

	if !p.ProbablyPrime(10) {
		t.Errorf("p isn't prime")
	}

	g := big.NewInt(2)

	s := rand.NewSource(time.Now().Unix())
	r := rand.New(s)

	a := big.NewInt(0)
	b := big.NewInt(0)

	a.Rand(r, p)
	b.Rand(r, p)

	dh1 := DiffieHelman{p, g, a}
	dh2 := DiffieHelman{p, g, b}

	A := dh1.PubKey()
	B := dh2.PubKey()

	sk1 := dh1.SessionKey(B)
	sk2 := dh2.SessionKey(A)

	if bytes.Compare(sk1[:], sk2[:]) != 0 {
		t.Errorf("session keys do not agree.")
	}
}
