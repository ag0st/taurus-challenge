// Package encdec provides the declaration of the methods NewHeader, NewDecReader and NewEncWriter. Theses two methods allows to encrypt and decrypt data
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
//     - The size of chunk is configurable on 64 unsigned integer
//     and if 0, there will be only one chunk.
//
//     - The IV is 12 bytes long (as recommended by NIST)
//
//     The Header :
//
//     0            50B        	  58B          70B
//     +-------------+----------------+------------+
//     |  Filename   |    Chunk Size  |     IV     |
//     +-------------+----------------+------------+
package encdec

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"io"

	"github.com/ag0st/taurus-challenge/errs"
)

const (
	filenameHeaderOffset        = 0
	filenameHeaderSize          = 50
	chunkHeaderOffset           = filenameHeaderOffset + filenameHeaderSize
	chunkHeaderSize             = 8
	ivHeaderSize                = 12
	ivHeaderOffset              = chunkHeaderOffset + chunkHeaderSize
	headerSizeByte              = filenameHeaderSize + chunkHeaderSize + ivHeaderSize
	tagSizeByte                 = 16
	keySize                     = 32
	seqNumSize                  = 4
	LAST_CHUNK_SEQ_NUM   uint32 = 0xFFFF_FFFF
)

var ErrFilenameTooLong error = errs.New(fmt.Sprintf("filename too long, max %d bytes", filenameHeaderSize))

type header [headerSizeByte]byte

func (h header) IV() []byte { return h[ivHeaderOffset : ivHeaderOffset+ivHeaderSize] }
func (h *header) SetIV(iv [ivHeaderSize]byte) {
	copy(h[ivHeaderOffset:ivHeaderOffset+ivHeaderSize], iv[:])
}
func (h header) ChunkSize() uint64 {
	return binary.BigEndian.Uint64(h[chunkHeaderOffset : chunkHeaderOffset+chunkHeaderSize])
}
func (h *header) SetChunkSize(size uint64) {
	binary.BigEndian.PutUint64(h[chunkHeaderOffset:chunkHeaderOffset+chunkHeaderSize], size)
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

func NewHeader(chunkSize uint64, filename string) header {
	h := header{}
	h.SetChunkSize(chunkSize)
	iv, err := generateIV()
	if err != nil {
		panic("Cannot generate the IV")
	}
	h.SetIV(iv)
	h.SetFilename(filename)
	return h
}

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


// generateIV creates a new IV
func generateIV() (iv [ivHeaderSize]byte, err error) {
	// generate a random IV. The IV is set to the header which is not encrypted but authentified.
	// The IV is not required to be secret.
	_, err = io.ReadFull(rand.Reader, iv[:])
	return
}