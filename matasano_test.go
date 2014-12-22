package matasano

import (
	"bytes"
	"encoding/hex"
	"reflect"
	"testing"
)

func TestEncryptionModeDetector(t *testing.T) {
	mode := EncryptionModeDetector(ByteAtATimeECBEncryptor)
	if mode != ECB {
		t.Errorf("guessed the wrong mode for the ByteAtATimeECBEncryptor")
	}
}

func TestDiscoverBlockSizeOfEncryptionOracle(t *testing.T) {
	size := DiscoverBlockSizeOfEncryptionOracle(ByteAtATimeECBEncryptor)
	if size != 16 {
		t.Errorf("got %v", size)
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
