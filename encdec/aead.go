package encdec

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"io"

	"golang.org/x/crypto/hkdf"
)

// This file contains the declaration of the methods Encrypt and Decrypt. Theses two methods allows to encrypt and decrypt data
// with AES GCM. This encryption method allow to authenticate the data for data-at-rest storage.
// In AES GCM, the IV hasn't to be secret and is already authenticated in the block encryption process, so no need to store it
// in the the addition data.
// There is two modes to encrypt and decrypt data:
//  1. One unique element -> The all data is encrypted as one
//  2. By chunk -> The data is spliced in chunk of exact same size and then encrypted individually
//
// For each data, we need to store at the beggining some information that can be passed in clear.
// For this, we define a header that will be present at the beggining of each encryption.
//
// The header must store: 1. Size of chunk (0 = mode 1.)
//  2. The IV
//
// The size of chunk is configurable on 32 unsigned integer (block size up to 4 GiB) and if 0, there will be only one chunk.
// The IV is 12 bytes long (as recommended by NIST)
// The Header :
//
//	0       4B              16B
//	+-------+-----------------+
//	|C Size |       IV        |
//	+-------+-----------------+
const (
	filenameHeaderOffset = 0
	filenameHeaderSize   = 50
	chunkHeaderOffset    = filenameHeaderOffset + filenameHeaderSize
	chunkHeaderSize      = 4
	ivHeaderSize         = 12
	ivHeaderOffset       = chunkHeaderOffset + chunkHeaderSize
	headerSizeByte       = filenameHeaderSize + chunkHeaderSize + ivHeaderSize
	tagSizeByte          = 16
	keySize              = 32
)

var filenameTooLong = errors.New("filename too long, max 50 bytes")

type header [headerSizeByte]byte

func (h header) IV() []byte { return h[ivHeaderOffset : ivHeaderOffset+ivHeaderSize] }
func (h *header) SetIV(iv [ivHeaderSize]byte) {
	copy(h[ivHeaderOffset:ivHeaderOffset+ivHeaderSize], iv[:])
}
func (h header) ChunkSize() uint32 {
	return binary.BigEndian.Uint32(h[chunkHeaderOffset : chunkHeaderOffset+chunkHeaderSize])
}
func (h *header) SetChunkSize(size uint32) {
	binary.BigEndian.PutUint32(h[chunkHeaderOffset:chunkHeaderOffset+chunkHeaderSize], size)
}
func (h *header) aad() []byte { return h[:filenameHeaderSize+chunkHeaderSize] }
func (h *header) SetFilename(filename string) error {
	if len(filename) > filenameHeaderSize {
		return filenameTooLong
	}
	copy(h[filenameHeaderOffset:filenameHeaderOffset + filenameHeaderSize], []byte(filename))
	return nil
}

// Encrypt reads the content from the reader and write it encrypted to the writer.
// The result is consitued of the header (non encrypted) then the encrypted data and finishing by the tag.
func Encrypt(ctx context.Context, w io.Writer, r io.Reader) error {
	key := ctx.Value("Key").([keySize]byte)
	// Create a new cipher
	block, err := aes.NewCipher(key[:])
	if err != nil {
		return err
	}

	iv, err := generateIV()
	if err != nil {
		return err
	}

	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return err
	}

	// create the buffer in which to store the encrypted data.
	plaintext, err := io.ReadAll(r)
	if err != nil {
		return err
	}
	plaintext = aesgcm.Seal(nil, iv[:], plaintext, nil)
	// add the header in front of the result
	h := header{}
	h.SetIV(iv)
	_, err = io.Copy(w, io.MultiReader(bytes.NewReader(h[:]), bytes.NewReader(plaintext)))
	return err
}

// Decrypt takes a reader containing the encrypted data and write the decrypted value into the writer.
func Decrypt(ctx context.Context, w io.Writer, r io.Reader) error {
	// First take the header
	var h [headerSizeByte]byte
	if _, err := io.ReadFull(r, h[:]); err != nil {
		return err
	}
	header := header(h)
	// Take the IV and the Key
	iv := header.IV()
	key := ctx.Value("Key").([keySize]byte)

	block, err := aes.NewCipher(key[:])
	if err != nil {
		return err
	}

	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return err
	}

	// create the buffer in which to store the encrypted data.
	cipher, err := io.ReadAll(r)
	if err != nil {
		return err
	}

	if _, err = aesgcm.Open(cipher[:0], iv[:], cipher[:], nil); err != nil {
		return err
	}
	// Remove the tag at the end
	_, err = io.Copy(w, bytes.NewReader(cipher[:len(cipher)-tagSizeByte]))
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
