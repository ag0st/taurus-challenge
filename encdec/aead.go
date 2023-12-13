// Package encdec provides the declaration of the methods Encrypt and Decrypt. Theses two methods allows to encrypt and decrypt data
// with AES GCM. This encryption method allow to authenticate the data for data-at-rest storage.
// In AES GCM, the IV hasn't to be secret and is already authenticated in the block encryption process, so no need to store it
// in the the addition data.
// There is two modes to encrypt and decrypt data:
//  1. One unique element -> The whole data is encrypted as one
//  2. By chunk -> The data is spliced in chunk of exact same size and then encrypted individually
//
// For each data, we need to store at the beggining some information that can be passed in clear.
// For this, we define a header that will be present at the beggining of each encryption.
//
// The header must store:
//
//  1. The filename
//
//  2. Size of chunk (0 = mode 1.)
//
//  3. The IV
//
//     - The filename is a byte array of maximum 50 bytes
//
//     - The size of chunk is configurable on 32 unsigned integer (block size up to 4 GiB)
//     and if 0, there will be only one chunk.
//
//     - The IV is 12 bytes long (as recommended by NIST)
//
//     The Header :
//
//     0            50B        	  54B          66B
//     +-------------+----------------+------------+
//     |  Filename   |    Chunk Size  |     IV     |
//     +-------------+----------------+------------+
package encdec

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"io"

	"golang.org/x/crypto/hkdf"
)

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

var ErrFilenameTooLong error = fmt.Errorf("filename too long, max %d bytes", filenameHeaderSize)

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
		return ErrFilenameTooLong
	}
	copy(h[filenameHeaderOffset:filenameHeaderOffset+filenameHeaderSize], []byte(filename))
	return nil
}
func (h *header) Filename() string {
	filename := h[filenameHeaderOffset : filenameHeaderOffset+filenameHeaderSize]
	return string(bytes.TrimRightFunc(filename, func(r rune) bool { return r == 0x0 }))
}

// Encrypt reads the content from the reader and write it encrypted to the writer.
// The result is consitued of the header (non encrypted) then the encrypted data and finishing by the tag.
func Encrypt(ctx context.Context, w io.Writer, r io.Reader, chunkSize uint32, filename string) error {
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
	wr, err := newEncWriter(key, h, w)
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
	reader, err := newDecReader(key, r)
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
