package matasano

import (
	"bufio"
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"os"
	"reflect"
	"testing"
)

func TestOracleEncryptionModeDetector(t *testing.T) {
	mode := OracleEncryptionModeDetector(ByteAtATimeECBEncryptor)
	if mode != ECB {
		t.Errorf("guessed the wrong mode for the ByteAtATimeECBEncryptor")
	}
}

func TestEncryptionModeDetector(t *testing.T) {
	detectEcbFile, err := os.Open("detectEcb.txt")
	if err != nil {
		t.Errorf("error reading test file: %v", err)
	}

	defer detectEcbFile.Close()

	var lines []string
	scanner := bufio.NewScanner(detectEcbFile)
	for scanner.Scan() {
		lines = append(lines, scanner.Text())
	}

	var ctBytes []byte
	var mode int
	found := false
	expectedIndex := 132

	for index, element := range lines {
		ctBytes, _ = hex.DecodeString(element)
		mode = EncryptionModeDetector(ctBytes)
		if mode == ECB {
			found = true
			if index != expectedIndex {
				t.Errorf("found ecb at unexpected index: %v", index)
			}
		}

	}

	if !found {
		t.Errorf("didn't find anything encrypted with ecb")
	}
}

func TestDiscoverBlockSizeOfEncryptionOracle(t *testing.T) {
	size := DiscoverBlockSizeOfEncryptionOracle(ByteAtATimeECBEncryptor)
	if size != 16 {
		t.Errorf("got %v", size)
	}
}

func TestByteAtATime(t *testing.T) {
	targetBytes, _ := base64.StdEncoding.DecodeString(targetB64PlainText)
	var empytyPrefix []byte
	pt := DecryptTarget(ByteAtATimeECBEncryptor, empytyPrefix, len(targetBytes))

	if bytes.Compare(pt, targetBytes) != 0 {
		t.Errorf("got %v, expected %v", pt, targetBytes)
	}
}

func TestByteAtATimeTricky(t *testing.T) {
	targetBytes, _ := base64.StdEncoding.DecodeString(targetB64PlainText)
	prefix, _ := base64.StdEncoding.DecodeString(prefixB64PlainText)

	pt := DecryptTarget(ByteAtATimeECBEncryptorTricky, prefix, len(targetBytes))
	if bytes.Compare(pt, targetBytes) != 0 {
		t.Errorf("got %v, expected %v", pt, targetBytes)
	}
}

func TestParseParamString(t *testing.T) {
	testString := "foo=bar&baz=qux&zap=zazzle"

	expected := make(map[string]string)
	expected["foo"] = "bar"
	expected["baz"] = "qux"
	expected["zap"] = "zazzle"

	actual := parseParamString(testString)

	eq := reflect.DeepEqual(expected, actual)

	if !eq {
		t.Errorf("got %v", actual)
	}
}

func TestUserEncode(t *testing.T) {
	u := User{"neal@neal.neal", "user", 10}
	if u.Encode() != "email=neal@neal.neal&uid=10&role=user" {
		t.Errorf("got %s", u.Encode())
	}
}

func TestGetMetacharacterFreeCipherText(t *testing.T) {
	testString := "iam16ch"
	key, _ := hex.DecodeString(fixedKeyString)

	ct := GetMetacharacterFreeCipherText(testString)
	pt := EcbDecrypt(key, ct)
	expectedPt := EcbDecrypt(key, EcbEncrypt(key, pt))
	if bytes.Compare(pt, expectedPt) != 0 {
		t.Errorf("got %v", pt)
	}
}

func TestCreateAdminProfileCipherText(t *testing.T) {
	ct := CreateAdminProfileCipherText()
	user := DecryptAndParseProfile(ct)

	if user.role != "admin" {
		t.Errorf("got %v", user.role)
	}
}

func TestPKCS7PaddingStripper(t *testing.T) {
	iceBytes := []byte("ICE ICE BABY\x04\x04\x04\x04")
	stripped, err := StripPKCS7Padding(iceBytes)
	expected := []byte("ICE ICE BABY")

	if err != nil {
		t.Errorf("got an error while stripping valid pkcs7 padding: %v", err)
	}
	if bytes.Compare(expected, stripped) != 0 {
		t.Errorf("expected %v, but got %v when stripping padding", expected, stripped)
	}
}

func TestCbcAdminBitFlipperRemovesAdminString(t *testing.T) {
	adminString := ";admin=true;"
	ct, iv := CbcBitFlipStringEncryptor(adminString)
	containsAdmin, err := CbcBitFlipIsAdmin(ct, iv)

	if err != nil {
		t.Errorf("got an unexpected error: %v", err)
	}

	if containsAdmin {
		t.Errorf("was able to sneak in ';admin=true;'")
	}
}

func TestForgeAdminCiphertext(t *testing.T) {
	ct, iv := ForgeAdminCiphertext()
	isAdmin, err := CbcBitFlipIsAdmin(ct, iv)

	if err != nil {
		t.Errorf("got an unexpected error: %v", err)
	}

	if !isAdmin {
		t.Errorf("failed to get admin=true.  Here's the ct: %v", ct)
	}
}
