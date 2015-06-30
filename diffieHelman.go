package matasano

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"math/big"
	mathrand "math/rand"
	"time"
)

const bigP = "ffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552bb9ed529077096966d670c354e4abc9804f1746c08ca237327ffffffffffffffff"

// DiffieHelman provides Diffie-Helman key exchange
type DiffieHelman struct {
	p       *big.Int
	g       *big.Int
	a       *big.Int
	B       *big.Int // public key of other party
	message []byte
}

// PubKey computes and returns the instance's public key (g**a mod p).
func (dh *DiffieHelman) PubKey() *big.Int {
	pubKey := big.NewInt(0)
	// We use -1 as a beacon to indicate that we should publish 0 as
	// our public key.
	if dh.a.Cmp(big.NewInt(-1)) != 0 {
		pubKey.Exp(dh.g, dh.a, dh.p)
	}

	return pubKey
}

// SessionKey performs Diffie-Helman key exchange.  It takes any public key as
// an argument, computes and returns a 256-bit session key.
func (dh *DiffieHelman) SessionKey() ([sha256.Size]byte, error) {
	if dh.B == big.NewInt(0) {
		var k [sha256.Size]byte
		return k, errors.New("no second public key available")
	}

	sessionKey := big.NewInt(0)
	// Having your secret set to -1 means your public key is just 0.
	// (This is not a mathematical fact; we've just used -1 as a beacon here.)
	if dh.a.Cmp(big.NewInt(-1)) != 0 {
		sessionKey = big.NewInt(0).Exp(dh.B, dh.a, dh.p)
	}

	sessionKeyBytes := sessionKey.Bytes()

	return sha256.Sum256(sessionKeyBytes), nil
}

func (dh *DiffieHelman) SendParameters(dhB *DiffieHelman) {
	dhB.ReceiveParameters(dh.p, dh.g, dh.PubKey())
}

func (dh *DiffieHelman) ReceiveParameters(p, g, A *big.Int) (dh_p, dh_g, dh_B *big.Int) {
	if (dh.p == nil && dh.g == nil) || (dh.p == p && dh.g == g) {
		dh.p = p
		dh.g = g
		dh.B = A
	}

	return dh.p, dh.g, dh.B
}

func (dh *DiffieHelman) SendMessage(m []byte, dhB *DiffieHelman) error {
	s, err := dh.SessionKey()
	if err != nil {
		return err
	}
	key := s[0:16]
	iv := make([]byte, 16)
	rand.Read(iv)
	enc := CbcEncryptor{key, iv}

	ct, err := enc.CbcEncrypt(m)
	if err != nil {
		return err
	}

	err = dhB.ReceiveMessage(append(iv, ct...))
	if err != nil {
		return err
	}

	return nil
}

func (dh *DiffieHelman) ReceiveMessage(m []byte) error {
	s, err := dh.SessionKey()
	if err != nil {
		return err
	}
	key := s[0:16]
	iv := m[0:16]
	ct := m[16:]
	enc := CbcEncryptor{key, iv}

	pt, err := enc.CbcDecrypt(ct)
	if err != nil {
		return err
	}

	dh.message = pt
	return nil
}

func createDhPair(p, g *big.Int) (dhA, dhB DiffieHelman) {
	s := mathrand.NewSource(time.Now().Unix())
	r := mathrand.New(s)

	a := big.NewInt(0)
	b := big.NewInt(0)

	a.Rand(r, p)
	b.Rand(r, p)

	dhA = DiffieHelman{p, g, a, big.NewInt(0), nil}
	dhB = DiffieHelman{p, g, b, big.NewInt(0), nil}

	return dhA, dhB
}

func Mitm(aToB, bToA []byte) (receivedByA, receivedByB, interceptedForA, interceptedForB []byte) {
	pBytes, _ := hex.DecodeString(bigP)
	p := big.NewInt(0)
	p.SetBytes(pBytes)
	g := big.NewInt(2)

	dhA, dhB := createDhPair(p, g)

	// We create two different instantions of Mallory, one each for talking to
	// A (dhMa) and B (dhMb)
	dhMa := DiffieHelman{p, g, big.NewInt(-1), big.NewInt(0), nil}
	dhMb := DiffieHelman{p, g, big.NewInt(-1), big.NewInt(0), nil}

	// Here's the key exchange with Mallory in the middle
	dhA.SendParameters(&dhMb)
	dhMb.SendParameters(&dhB)
	dhB.SendParameters(&dhMa)
	dhMa.SendParameters(&dhA)

	dhA.SendMessage(aToB, &dhMb)
	dhMb.SendMessage(dhMb.message, &dhB)
	dhB.SendMessage(bToA, &dhMa)
	dhMa.SendMessage(dhMa.message, &dhA)

	return dhA.message, dhB.message, dhMa.message, dhMb.message
}
