package matasano

import (
	"bytes"
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
