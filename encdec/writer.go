package encdec

import (
	"bytes"
	"crypto/cipher"
	"encoding/binary"
	"errors"
	"io"
)

// Errors declarations
var (
	ErrTooMuchChunk error = errors.New("too much chunk produced. Max = 0xFFFF_FFFF")
	ErrNoLastChunk  error = errors.New("no last chunk to write when closing the writer")
	ErrWriteClosed  error = errors.New("writer already closed")
)

// newEncWriter creates the right type of writer regarding the data stored inside the header.
// It can create chunk writer or whole writer.
func newEncWriter(key [keySize]byte, header header, dest io.Writer) (io.WriteCloser, error) {
	cipher, err := newCipher(key)
	if err != nil {
		return nil, err
	}
	if header.ChunkSize() > 0 {
		return newEncChunkWriter(header, dest, cipher), nil
	} else {
		return newEncWholeWriter(header, dest, cipher), nil
	}
}

// newEncChunkWriter creates a new encChunkWriter that implement encryption in chunk method.
func newEncChunkWriter(h header, dest io.Writer, aesgcm cipher.AEAD) *encChunkWriter {
	return &encChunkWriter{
		dest:       dest,
		isClosed:   false,
		aesgcm:     aesgcm,
		currSeqNum: 0,
		header:     h,
		offset:     0,
		buf:        make([]byte, h.ChunkSize()),
		firstWrite: true,
	}
}

// encChunkWriter wraps a Writer and encrypt data before passing it to the writer.
// It is a WriteCloser.
// It first copy plaintext into its internal buffer and then encrypt it to push it into the writer.
// It keeps always a fully plaintext chunk inside its buffer for the closing stage
// where it set last chunk flag and push a last time into the writer before closing.
type encChunkWriter struct {
	dest       io.Writer
	buf        []byte      // buffer to retain at least a chunk. Plaintext
	isClosed   bool        // indicate if the writer is closed
	aesgcm     cipher.AEAD // The standard implementation of a cipher AEAD
	currSeqNum uint32      // current sequence number
	header     header      // Header that store the configuration of the encryption
	offset     int         // Greater than 0 if something is into buf
	firstWrite bool        // used to write the header on the first time
}

func (ew *encChunkWriter) Write(p []byte) (n int, err error) {
	if ew.isClosed {
		return 0, ErrWriteClosed
	}
	if ew.firstWrite {
		// Write the header
		ew.firstWrite = false
		_, err = ew.dest.Write(ew.header[:])
		if err != nil {
			ew.isClosed = true
			return 0, err
		}
	}
	// encrypt until we have read everything and that it remains enough for a last chunk
	for n < len(p) && len(p)-n > int(ew.header.ChunkSize())-ew.offset {
		// copy the maximum we can into our buffer
		// The buffer will be fulfilled regarding the condition of the for
		n += copy(ew.buf[ew.offset:], p[n:])
		ew.offset = 0

		// Encrypt the data

		ew.dest.Write(ew.sealBuf(false))
		ew.currSeqNum++
		// check we did not passed the maximum seq number
		if ew.currSeqNum == LAST_CHUNK_SEQ_NUM {
			return n, ErrTooMuchChunk
		}
	}
	// copy the last bits of data into the buffer
	bn := copy(ew.buf[ew.offset:], p[n:])
	ew.offset += bn
	n += bn
	if n < len(p) {
		return n, io.ErrShortWrite
	}
	return
}

// Close closes the encChunkWriter by pushing the last chunk into the destination and close
// the destination if needed.
func (ew *encChunkWriter) Close() error {
	ew.isClosed = true
	if ew.offset == 0 {
		return ErrNoLastChunk
	}
	_, err := ew.dest.Write(ew.sealBuf(true))
	if w, ok := ew.dest.(io.WriteCloser); ok {
		return w.Close()
	}
	return err
}

// sealBuf seal the current plaintext buffer and return the encrypted result.
// This result can then be used to push into the underlying writer.
// isFinal must be only used once for the writer, it seals the final chunk.
// The user must assured that the plaintext buffer is not empty before calling this method.
func (ew *encChunkWriter) sealBuf(isFinal bool) []byte {
	// 1. we need to build the IV for this chunk, embed the sequence number
	currentIV := ew.header.IV()
	var destSize uint32 = seqNumSize + tagSizeByte
	currentSeqNum := ew.currSeqNum
	if isFinal { // if is final chunk, put 0xFFFF_FFFF as sequence number
		currentSeqNum = LAST_CHUNK_SEQ_NUM
		destSize += uint32(ew.offset)
		ew.buf = ew.buf[:ew.offset] // limit the plaintext to write
	} else {
		destSize += ew.header.ChunkSize()
	}
	binary.BigEndian.PutUint32(currentIV[ivHeaderSize-seqNumSize:], binary.BigEndian.Uint32(currentIV[ivHeaderSize-seqNumSize:])^currentSeqNum)
	// 2. Encrypt the data
	toPush := make([]byte, destSize)
	ew.aesgcm.Seal(toPush[seqNumSize:seqNumSize], currentIV, ew.buf, ew.header.aad())
	// 3. Push the encrypted data to the writer
	binary.BigEndian.PutUint32(toPush[:seqNumSize], currentSeqNum)
	return toPush
}

// encWholeWriter is an io.WriteCloser. It encrypts the data as a whole.
// It first stores all the data into its internal buffer
// and then encrypt and push to the underlying writer when the Close is called.
type encWholeWriter struct {
	dest   io.Writer
	buf    []byte      // buffer to retain at least a chunk. Plaintext
	aesgcm cipher.AEAD // The standard implementation of a cipher AEAD
	header header      // Header that store the configuration of the encryption
}

// newEncWholeWriter creates a new encWholeWriter
func newEncWholeWriter(h header, dest io.Writer, aesgcm cipher.AEAD) *encWholeWriter {
	return &encWholeWriter{
		dest:   dest,
		aesgcm: aesgcm,
		header: h,
	}
}

// Write is the implemention of write of the encWholeWriter. It only stores data into its internal
// buffer. The encryption is done in the Close function.
func (eww *encWholeWriter) Write(p []byte) (n int, err error) {
	// Add the data to the internal buffer
	eww.buf = append(eww.buf, p...)
	return len(p), nil
}

// Close is the implementation of the Close function of a encWholeWriter. It Seals the data
// it has stored and push them into the underlying writer.
func (eww *encWholeWriter) Close() error {
	// Seal the data and push it to the underlying writer
	toPush := eww.aesgcm.Seal(nil, eww.header.IV(), eww.buf, eww.header.aad())
	_, err := io.Copy(eww.dest, io.MultiReader(bytes.NewReader(eww.header[:]), bytes.NewReader(toPush)))
	return err
}
