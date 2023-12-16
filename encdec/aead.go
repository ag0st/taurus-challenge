package encdec

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"io"

	"golang.org/x/crypto/hkdf"
)

// Encrypt reads the content from the reader and write it encrypted to the writer.
// The result is consitued of the header (non encrypted) then the encrypted data and finishing by the tag.
func Encrypt(ctx context.Context, w io.Writer, r io.Reader, chunkSize uint64, filename string) error {
	key := ctx.Value("Key").([keySize]byte)
	iv, err := generateIV()
	if err != nil {
		return err
	}

	h := header{}
	h.SetChunkSize(chunkSize)
	h.SetIV(iv)
	h.SetFilename(filename)

	// create the writer
	wr, err := NewEncWriter(key, h, w)
	if err != nil {
		return err
	}
	_, err = io.Copy(wr, r)
	if err != nil {
		return err
	}
	err = wr.Close()
	return err
}

// Decrypt takes a reader containing the encrypted data and write the decrypted value into the writer.
func Decrypt(ctx context.Context, w io.Writer, r io.Reader) error {
	key := ctx.Value("Key").([keySize]byte)
	reader, err := NewDecReader(key, r)
	io.Copy(w, reader)
	return err
}

// generateIV creates a new IV
func generateIV() (iv [ivHeaderSize]byte, err error) {
	// generate a random IV. The IV is set to the header which is not encrypted but authentified.
	// The IV is not required to be secret.
	_, err = io.ReadFull(rand.Reader, iv[:])
	return
}

// deriveKey derives a new key from the master key and a random number.
func deriveKey(randn [keySize]byte, masterKey [keySize]byte) (key [keySize]byte, err error) {
	// Generate a new key from the IV and the master key to encrypt the file.
	// Generating a new Key for each file ensure that some blocks of the file is not altered with another block of different file.
	kdf := hkdf.New(sha256.New, masterKey[:], randn[:], nil)
	_, err = io.ReadFull(kdf, key[:])
	return
}
