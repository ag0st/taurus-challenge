package encdec

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/binary"
	"errors"
	"io"
)

// This files contains two readers:
//		- encReader which encrypts the data it reads
//		- decReader which decrypts the data it reads
// Both implement chunk encryption. It means that the encReader will read the data and split them by chunk
// (size defined in the parameters). For each chunk of data, it will encrypt them individually. The decReader will
// consider that the data it has to read are in form of chunk.
// For each chunk, we need to know a sequence number to be able to put them back in the
// right order. In order to authenticate automatically the sequence number, each chunk is
// encrypted using the IV as IV xor SeqNum.
// This technic implies that for each chunk, we need to store the IV that has been used.
// We consider that the base IV is the same for each chunk and the size of each chunk is also the same,
// so it is stored at the beginning of the sequence, like for the standard encryption pattern.
// The sequence number is written on 4 bytes. The last chunk in a sequence get the number 0xFFFF_FFFF

const seqNumSize = 4
const LAST_CHUNK_SEQ_NUM uint32 = 0xFFFF_FFFF

var ErrInvalidSeqNum error = errors.New("chunk in invalid sequence")
var ErrTooMuchChunk error = errors.New("too much chunk produced. Max = 0xFFFF_FFFF")
var ErrNoLastChunk error = errors.New("no last chunk to write when closing the writer")
var ErrWriteClosed error = errors.New("writer already closed")

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

type decReader struct {
	aesgcm     cipher.AEAD // The standard implementation of a cipher AEAD
	buf        []byte      // buffer for already decrypted plaintext that have not been passed to the destination
	src        io.Reader   // the source reader
	firstRead  bool        // Used for the first time we read from the source, to extract the header
	header     header      // Store the header on the first read for later easy access
	currSeqNum uint32      // used to check if the read sequence is in order
	isFinished bool
}

func newDecReader(key [keySize]byte, src io.Reader) (io.Reader, error) {
	// Get the key from the context
	cipher, err := newCipher(key)
	if err != nil {
		return nil, err
	}
	return &decReader{
		aesgcm:     cipher,
		src:        src,
		firstRead:  true,
		currSeqNum: 0,
		isFinished: false,
	}, nil
}

func (dr *decReader) Read(p []byte) (n int, err error) {
	if dr.isFinished {
		return 0, io.EOF
	}
	if dr.firstRead {
		// Extract the header
		// Take the header from the reader
		var h [headerSizeByte]byte
		if n, err := io.ReadFull(dr.src, h[:]); err != nil {
			return n, err
		}
		header := header(h)
		dr.header = header
		dr.firstRead = false
	}

	// While it remains place in p, we decrypt a chunk and put it into p
	for n < len(p) && !dr.isFinished {
		// If we already decrypted data that have not been passed, give them now
		if len(dr.buf) > 0 {
			n += copy(p, dr.buf)
			// remove the text we just pushed from the buffer
			dr.buf = dr.buf[n:]
			// it forces to redo the check for us
			continue
		}
		// Here we know that the buffer is empty, if not, we would have returned before.

		// Create a buffer for encrypted data
		cipherBuf := make([]byte, dr.header.ChunkSize()+seqNumSize+tagSizeByte)

		// Read the cipher text into our cipher buffer for decryption
		nn, err := io.ReadFull(dr.src, cipherBuf)
		if err != nil && err != io.ErrUnexpectedEOF { // we got an error that is not an EOF, return error
			dr.isFinished = true
			return n, err
		}
		// We may have reached the last chunk if an unexpected eof appears (see ReadAll documentation)
		if nn > 0 && err == io.ErrUnexpectedEOF {
			if binary.BigEndian.Uint32(cipherBuf[:seqNumSize]) != LAST_CHUNK_SEQ_NUM {
				dr.isFinished = true
				return n, err
			} else {
				// shrink the buffer to its right size
				cipherBuf = cipherBuf[:nn]
			}
		}

		// Build the correct IV by xoring with the sequence number
		currentIV := dr.header.IV()
		currentSeqNum := binary.BigEndian.Uint32(cipherBuf[:seqNumSize])
		binary.BigEndian.PutUint32(currentIV[ivHeaderSize-seqNumSize:], binary.BigEndian.Uint32(currentIV[ivHeaderSize-seqNumSize:])^currentSeqNum)

		// Check the validity of the sequence number, if we encountered the last chunk, no check
		if currentSeqNum != dr.currSeqNum {
			if currentSeqNum == LAST_CHUNK_SEQ_NUM {
				dr.isFinished = true
			} else {
				return 0, ErrInvalidSeqNum
			}
		}
		dr.currSeqNum++

		// Decryption

		// If there is enough place into p for the chunk, decrypt directly into it.
		// Else decrypt it into the plaintext buffer, the next loop will push it into p
		if len(p)-n >= nn-seqNumSize-tagSizeByte {
			_, err = dr.aesgcm.Open(p[n:n], currentIV, cipherBuf[seqNumSize:], dr.header.aad())
			n += nn - seqNumSize - tagSizeByte
		} else {
			dr.buf, err = dr.aesgcm.Open(nil, currentIV, cipherBuf[seqNumSize:], dr.header.aad())
			dr.buf = dr.buf[:len(dr.buf)-tagSizeByte] // remove the tag
		}

		if err != nil {
			return n, err
		}
	}

	// if we finished before filling entirely p, it means we encoutered an UnexpectedEOF.
	if dr.isFinished {
		err = io.EOF
	}
	return
}

// encWriter wraps a Writer and encrypt data before passing it to the writer.
// It is a WriteCloser.
// It first copy plaintext into its internal buffer and then encrypt it to push it into the writer.
// It keeps always a fully plaintext chunk inside its buffer for the closing stage
// where it set last chunk flag and push a last time into the writer before closing.
type encWriter struct {
	dest       io.Writer
	buf        []byte      // buffer to retain at least a chunk. Plaintext
	isClosed   bool        // indicate if the writer is closed
	aesgcm     cipher.AEAD // The standard implementation of a cipher AEAD
	currSeqNum uint32      // current sequence number
	header     header      // Header that store the configuration of the encryption
	offset     int         // Greater than 0 if something is into buf
	firstWrite bool        // used to write the header on the first time
}

func newEncWriter(key [keySize]byte, header header, dest io.Writer) (io.WriteCloser, error) {
	cipher, err := newCipher(key)
	if err != nil {
		return nil, err
	}
	return &encWriter{
		dest:       dest,
		isClosed:   false,
		aesgcm:     cipher,
		currSeqNum: 0,
		header:     header,
		offset:     0,
		buf:        make([]byte, header.ChunkSize()),
		firstWrite: true,
	}, nil
}

func (ew *encWriter) Write(p []byte) (n int, err error) {
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

// Close closes the encWriter by pushing the last chunk into the destination and close
// the destination if needed.
func (ew *encWriter) Close() error {
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

func (ew *encWriter) sealBuf(isFinal bool) []byte {
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
