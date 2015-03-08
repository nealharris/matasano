package matasano

import (
	"bytes"
	cryptorand "crypto/rand"
	mathrand "math/rand"
	"testing"
)

func TestForgeKeyedSha(t *testing.T) {
	keyLength := mathrand.Intn(32)
	msgLength := mathrand.Intn(1000)
	key := make([]byte, keyLength)
	msg := make([]byte, msgLength)
	cryptorand.Read(key)
	cryptorand.Read(msg)

	example := BadMac(key, msg)
	forged := ForgeKeyedSha([]byte("append"), example, len(msg)+len(key))

	orig := mdPad(append(key, msg...))[len(key):]
	appended := append(orig, []byte("append")...)
	legit := BadMac(key, appended)

	if bytes.Compare(legit[:], forged[:]) != 0 {
		t.Errorf("failure!, %v, %v", convertShaToH(legit), convertShaToH(forged))
	}
}
