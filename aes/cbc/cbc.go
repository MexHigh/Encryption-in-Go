package cbc

import (
	"myprojects/encryption/aes"
)

// CBC defines an aes-cbc engine used to encrypt and decrypt things
type CBC struct {
	Params aes.Params
}

// NewCBCWithRandKey returns a new CBC object with generated Key
func NewCBCWithRandKey(strength int) (CBC, error) {
	params, err := aes.NewParams(strength)
	if err != nil {
		return CBC{}, err
	}
	return CBC{params}, nil
}

// Encrypt encrypts cleartext with key
func (c CBC) Encrypt(cleartext string) (string, error) {
	return "", nil
}

// Decrypt decrypts ciphertext with key
func (c CBC) Decrypt(ciphertext string) (string, error) {
	return "", nil
}
