package aes

import (
	"crypto/rand"
	"errors"
)

// Cipher defines a encrypt- and decryptable struct
type Cipher interface {
	Encrypt(string) string
	Decrypt(string) string
}

// Params hold the key, it's strength and the number of aes rounds
type Params struct {
	Key      []byte
	Strength int
	Rounds   int
}

// NewParams generates a new AES key
func NewParams(strength int) (Params, error) {
	if strength != 128 && strength != 192 && strength != 265 {
		return Params{}, errors.New("NewKey only accepts 128, 192 and 265 as key strength")
	}
	k := make([]byte, strength/8)
	_, err := rand.Read(k)
	if err != nil {
		return Params{}, err
	}
	var rounds int
	switch strength {
	case 265:
		rounds = 14
	case 192:
		rounds = 12
	case 128:
		rounds = 10
	default:
		return Params{}, errors.New("Usually unrechable code reached while creating new aes key")
	}
	return Params{k, strength, rounds}, nil
}

func (p Params) keyAddition(m string) (string, error) {
	return "", nil
}

func (p Params) substitution(m string) (string, error) {
	return "", nil
}

func (p Params) shiftRow(m string) (string, error) {
	return "", nil
}

func (p Params) mixColumns(m string) (string, error) {
	return "", nil
}

// DoRound runs one aes round
func (p Params) DoRound(round int, in string) (string, error) {
	var err error
	var m string = in
	m, err = p.keyAddition(m)
	if err != nil {
		return "", err
	}
	m, err = p.substitution(m)
	if err != nil {
		return "", err
	}
	m, err = p.shiftRow(m)
	if err != nil {
		return "", err
	}
	m, err = p.mixColumns(m)
	if err != nil {
		return "", err
	}
	if round == p.Rounds {
		m, err = p.keyAddition(m)
		if err != nil {
			return "", err
		}
	}
	return m, nil
}
