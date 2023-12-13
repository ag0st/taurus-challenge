package encdec

import (
	"crypto/aes"
	"crypto/cipher"
)

// newCipher create a new aes gcm cipher from the standard library.
func newCipher(key [keySize]byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(key[:])
	if err != nil {
		return nil, err
	}
	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	return aesgcm, nil

}