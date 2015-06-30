package matasano

import (
	"bytes"
	"encoding/hex"
	"math/big"
	"testing"
)

func TestMessageSending(t *testing.T) {
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

	dh1, dh2 := createDhPair(p, g)

	dh1.SendParameters(&dh2)
	dh2.SendParameters(&dh1)

	sk1, err := dh1.SessionKey()
	if err != nil {
		t.Errorf("error during session key calculation: %g", err)
	}
	sk2, err := dh2.SessionKey()
	if err != nil {
		t.Errorf("error during session key calculation: %g", err)
	}

	if bytes.Compare(sk1[:], sk2[:]) != 0 {
		t.Errorf("session keys do not agree.")
	}

	message := []byte("test message 123") // exactly 16 bytes to make comparison below simpler
	err = dh1.SendMessage(message, &dh2)
	if err != nil {
		t.Errorf("error during message transmission: %g", err)
	}
	if bytes.Compare(message, dh2.message) != 0 {
		t.Errorf("message sent (%s) does match message received on other side (%s)", message, dh2.message)
	}
}

func TestMitm(t *testing.T) {
	// messages purposely 16 bytes long to make comparison simpler
	aToB := []byte("To B. Love, A :)")
	bToA := []byte("To A. Love, B :)")
	receivedByA, receivedByB, interceptedForA, interceptedForB := Mitm(aToB, bToA)

	if bytes.Compare(aToB, receivedByB) != 0 {
		t.Errorf("message from A to B corrupted by Mallory! sent: %g, received: %g", aToB, receivedByB)
	}

	if bytes.Compare(bToA, receivedByA) != 0 {
		t.Errorf("message from B to A corrupted by Mallory! sent: %g, received: %g", bToA, receivedByA)
	}

	if bytes.Compare(aToB, interceptedForB) != 0 {
		t.Errorf("message from A to B not decrypted correctly by Mallory! sent: %g, received: %g", aToB, interceptedForB)
	}

	if bytes.Compare(bToA, interceptedForA) != 0 {
		t.Errorf("message from B to A not decrypted correctly by Mallory! sent: %g, received: %g", bToA, interceptedForA)
	}
}
