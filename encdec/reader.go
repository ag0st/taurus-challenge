package encdec

import (
	"crypto/cipher"
	"encoding/binary"
	"errors"
	"io"
)

// This files contains two readers:
//		- encReader which encrypts the data it reads
//		- decChunkReader which decrypts the data it reads
// Both implement chunk encryption. It means that the encReader will read the data and split them by chunk
// (size defined in the parameters). For each chunk of data, it will encrypt them individually. The decChunkReader will
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

// Errors declarations
var (
	ErrInvalidSeqNum error = errors.New("chunk in invalid sequence")
	ErrNoFirstRead   error = errors.New("not already read the header")
)

// DecReader is a decrypting reader. It wraps an io.Reader and allow decryption
// during the read.
type decReader interface {
	io.Reader
	// gives the header of the current data
	getHeader() *header
}

func newDecReader(key [keySize]byte, src io.Reader) (io.Reader, error) {
	// Get the key from the context
	cipher, err := newCipher(key)
	if err != nil {
		return nil, err
	}
	return &decModeReader{
		firstRead: true,
		src:       src,
		aesgcm:    cipher,
	}, nil
}


type decModeReader struct {
	reader    decReader
	firstRead bool
	src       io.Reader
	aesgcm    cipher.AEAD // The standard implementation of a cipher AEAD
}

func (dmr *decModeReader) Read(p []byte) (n int, err error) {
	if dmr.firstRead {
		// Extract the header
		// Take the header from the reader
		var h [headerSizeByte]byte
		if n, err := io.ReadFull(dmr.src, h[:]); err != nil {
			return n, err
		}
		header := header(h)

		// create the correct reader regarding the mode
		var reader decReader
		if header.ChunkSize() > 0 {
			reader = newDecChunkReader(dmr.aesgcm, header, dmr.src)
		} else {
			reader = newDecWholeReader(dmr.aesgcm, header, dmr.src)
		}
		dmr.reader = reader
		dmr.firstRead = false

		// call the first read to add n to the number of bytes read
		nn, err := dmr.reader.Read(p)
		return nn + n, err
	}
	return dmr.reader.Read(p)
}

// filename gives the name of the file currently in decryption.
// If the header of the stream has not yet been read (no first read),
// it returns an ErrNoFirstRead error.
func (dmr *decModeReader) filename() (string, error) {
	if dmr.firstRead {
		return "", ErrNoFirstRead
	}
	return dmr.reader.getHeader().Filename(), nil
}

// decChunkReader is an implementation of decReader that decrypt using the chunk technique.
// It is used as a wrapper around another reader.
type decChunkReader struct {
	aesgcm     cipher.AEAD // The standard implementation of a cipher AEAD
	buf        []byte      // buffer for already decrypted plaintext that have not been passed to the destination
	src        io.Reader   // the source reader
	firstRead  bool        // Used for the first time we read from the source, to extract the header
	header     header      // Store the header on the first read for later easy access
	currSeqNum uint32      // used to check if the read sequence is in order
	isFinished bool
}

func (dr *decChunkReader) getHeader() *header {
	return &dr.header
}

// newDecReader creates a new reader that wraps the one given in parameter and
// allow automatic decryption of the data comming from the underlying reader.
func newDecChunkReader(cipher cipher.AEAD, h header, src io.Reader) decReader {
	return &decChunkReader{
		aesgcm:     cipher,
		src:        src,
		firstRead:  true,
		currSeqNum: 0,
		isFinished: false,
		header:     h,
	}
}

func (dr *decChunkReader) Read(p []byte) (n int, err error) {
	if dr.isFinished {
		return 0, io.EOF
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

type decWholeReader struct {
	src       io.Reader
	buf       []byte
	header    header
	aesgcm    cipher.AEAD
	decrypted bool
}

func newDecWholeReader(cipher cipher.AEAD, h header, src io.Reader) decReader {
	return &decWholeReader{
		src: src,
		header: h,
		aesgcm: cipher,
		decrypted: false,
	}
}

func (dwr *decWholeReader) Read(p []byte) (n int, err error) {
	if !dwr.decrypted {
		// Take the IV and the Key
		iv := dwr.header.IV()
		// read the whole data in memory
		dwr.buf, err = io.ReadAll(dwr.src)
		if err != nil {
			return 0, err
		}
		// decrypt the whole data in memory
		if _, err = dwr.aesgcm.Open(dwr.buf[:0], iv, dwr.buf, dwr.header.aad()); err != nil {
			return 0, err
		}
		// Remove the tag at the end
		dwr.buf = dwr.buf[:len(dwr.buf)-tagSizeByte]
	}

	// push the maximum
	n = copy(p, dwr.buf)
	return n, nil
}

func (dwr *decWholeReader) getHeader() *header {
	return &dwr.header
}
