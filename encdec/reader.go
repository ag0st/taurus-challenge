package encdec

import (
	"crypto/cipher"
	"encoding/binary"
	"io"

	"github.com/ag0st/taurus-challenge/errs"
)

// This files contains two readers:
//		- decWholeReader which waits on the whole data to decrypt it.
//		- decChunkReader which decrypts the data it reads chunk by chunk (stream)
// The decChunkReader will consider that the data it has to read are in form of chunk.
// For each chunk, we need to know a sequence number to be able to put them back in the
// right order. In order to authenticate automatically the sequence number, each chunk is
// encrypted using the IV as IV xor SeqNum.
// This technic implies that for each chunk, we need to store the IV that has been used.
// We consider that the base IV is the same for each chunk and the size of each chunk is also the same,
// so it is stored at the beginning of the sequence, like for the standard encryption pattern.
// The sequence number is written on 4 bytes. The last chunk in a sequence get the number 0xFFFF_FFFF

// Errors declarations
var (
	ErrInvalidSeqNum error = errs.New("chunk in invalid sequence")
	ErrNoFirstRead   error = errs.New("not already read the header")
)

// Reader is a decrypting reader. It wraps an io.Reader and allow decryption
// during the read.
type Reader interface {
	io.Reader
	io.WriterTo
	// gives the header of the current data
	Filename() (string, error)
}

// subReader is an interface representing a reader inside the
// decModeReader structure. It is the underlying decryption reader of the
// structure.
type subReader interface {
	io.Reader
	io.WriterTo
	getHeader() *header
}

// NewDecReader creates a new deryption reader able to decrypt an encrypted file
// with a encdec.EncWriter
func NewDecReader(key [keySize]byte, src io.Reader) (Reader, error) {
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

// decModeReader is a wrapper structure around the a decryption reader.
// it allow to create one object that is able to initialize the right
// reader on the first read (need to have the header to know which reader
// to create).
type decModeReader struct {
	reader    subReader
	firstRead bool
	src       io.Reader
	aesgcm    cipher.AEAD // The standard implementation of a cipher AEAD
}

func (dmr *decModeReader) Read(p []byte) (n int, err error) {
	if dmr.firstRead {
		// Extract the header
		n, err := dmr.readHeader()
		if err != nil {
			return n, err
		}
		nn, err := dmr.reader.Read(p)
		return nn, err
	}
	return dmr.reader.Read(p)
}

// filename gives the name of the file currently in decryption.
// If the header of the stream has not yet been read (no first read),
// it returns an ErrNoFirstRead error.
func (dmr *decModeReader) Filename() (string, error) {
	if dmr.firstRead {
		return "", ErrNoFirstRead
	}
	return dmr.reader.getHeader().Filename(), nil
}

// WriteTo call the inside WriterTo (reader) method.
// It also reads the header first before calling WriteTo
func (dmr *decModeReader) WriteTo(w io.Writer) (int64, error) {
	n, err := dmr.readHeader()
	if err != nil {
		return int64(n), err
	}
	return dmr.reader.WriteTo(w)
}

// readHeader reads the first bytes of the src reader to construct the header.
// It initialize the inner reader (chunk or whole).
func (dmr *decModeReader) readHeader() (int, error) {
	if dmr.firstRead {
		// Extract the header
		// Take the header from the reader
		var h [headerSizeByte]byte
		n, err := io.ReadFull(dmr.src, h[:])
		if err != nil {
			return n, err
		}
		header := header(h)

		// create the correct reader regarding the mode
		var reader subReader
		if header.ChunkSize() > 0 {
			reader = newDecChunkReader(dmr.aesgcm, header, dmr.src)
		} else {
			reader = newDecWholeReader(dmr.aesgcm, header, dmr.src)
		}
		dmr.reader = reader
		dmr.firstRead = false

		return n, err
	}
	return 0, nil
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

func (dcr *decChunkReader) getHeader() *header {
	return &dcr.header
}

// newDecReader creates a new reader that wraps the one given in parameter and
// allow automatic decryption of the data comming from the underlying reader.
func newDecChunkReader(cipher cipher.AEAD, h header, src io.Reader) subReader {
	return &decChunkReader{
		aesgcm:     cipher,
		src:        src,
		firstRead:  true,
		currSeqNum: 0,
		isFinished: false,
		header:     h,
	}
}

func (dcr *decChunkReader) Read(p []byte) (n int, err error) {
	if dcr.isFinished {
		return 0, io.EOF
	}

	// While it remains place in p, we decrypt a chunk and put it into p
	for n < len(p) && !dcr.isFinished {
		// If we already decrypted data that have not been passed, give them now
		if len(dcr.buf) > 0 {
			n += copy(p, dcr.buf)
			// remove the text we just pushed from the buffer
			dcr.buf = dcr.buf[n:]
			// it forces to redo the check for us
			continue
		}
		// Here we know that the buffer is empty, if not, we would have returned before.

		// Create a buffer for encrypted data
		cipherBuf := make([]byte, dcr.header.ChunkSize()+seqNumSize+tagSizeByte)

		// Read the cipher text into our cipher buffer for decryption
		nn, err := io.ReadFull(dcr.src, cipherBuf)
		if err != nil && err != io.ErrUnexpectedEOF { // we got an error that is not an EOF, return error
			dcr.isFinished = true
			return n, err
		}
		// We may have reached the last chunk if an unexpected eof appears (see ReadAll documentation)
		if nn > 0 && err == io.ErrUnexpectedEOF {
			if binary.BigEndian.Uint32(cipherBuf[:seqNumSize]) != LAST_CHUNK_SEQ_NUM {
				dcr.isFinished = true
				return n, err
			} else {
				// shrink the buffer to its right size
				cipherBuf = cipherBuf[:nn]
			}
		}

		// Build the correct IV by xoring with the sequence number
		currentIV := dcr.header.IV()
		currentSeqNum := binary.BigEndian.Uint32(cipherBuf[:seqNumSize])
		binary.BigEndian.PutUint32(currentIV[ivHeaderSize-seqNumSize:], binary.BigEndian.Uint32(currentIV[ivHeaderSize-seqNumSize:])^currentSeqNum)

		// Check the validity of the sequence number, if we encountered the last chunk, no check
		if currentSeqNum != dcr.currSeqNum {
			if currentSeqNum == LAST_CHUNK_SEQ_NUM {
				dcr.isFinished = true
			} else {
				return 0, ErrInvalidSeqNum
			}
		}
		dcr.currSeqNum++

		// Decryption

		// If there is enough place into p for the chunk, decrypt directly into it.
		// Else decrypt it into the plaintext buffer, the next loop will push it into p
		if len(p)-n >= nn-seqNumSize-tagSizeByte {
			_, err = dcr.aesgcm.Open(p[n:n], currentIV, cipherBuf[seqNumSize:], dcr.header.aad())
			n += nn - seqNumSize - tagSizeByte
		} else {
			dcr.buf, err = dcr.aesgcm.Open(nil, currentIV, cipherBuf[seqNumSize:], dcr.header.aad())
			dcr.buf = dcr.buf[:len(dcr.buf)-tagSizeByte] // remove the tag
		}

		if err != nil {
			return n, err
		}
	}

	// if we finished before filling entirely p, it means we encoutered an UnexpectedEOF.
	if dcr.isFinished {
		err = io.EOF
	}
	return
}

// WriteTo is the implementation of WriteTo of the io.WriterTo
func (dcr *decChunkReader) WriteTo(w io.Writer) (n int64, err error) {
	// Reads chunk by chunk and push them into the writer
	var buffer = make([]byte, dcr.header.ChunkSize())
	for {
		nr, err := dcr.Read(buffer[:])
		if err != nil {
			if err == io.EOF && nr == 0 {
				break
			} else if err != io.EOF {
				return n, err
			}
		}
		nn, err := w.Write(buffer[:nr])
		n += int64(nn)
		if err != nil {
			return n, err
		}
	}
	return n, err
}

// decWholeReader is a decryption reader that waits until the whole
// data is inside its buffer to decrypt it in one time.
type decWholeReader struct {
	src       io.Reader
	buf       []byte
	header    header
	aesgcm    cipher.AEAD
	decrypted bool
}

// newDecWholeReader creates a new reader creates a new decryption reader
// that decrypt the file as a whole.
// Can take a lot of memory.
func newDecWholeReader(cipher cipher.AEAD, h header, src io.Reader) subReader {
	return &decWholeReader{
		src:       src,
		header:    h,
		aesgcm:    cipher,
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

func (dwr *decWholeReader) WriteTo(w io.Writer) (n int64, err error) {
	// Reads the whole file and push the result into the writer
	data, err := io.ReadAll(dwr)
	if err != nil {
		return int64(len(data)), err
	}
	nn, err := w.Write(data)
	return int64(nn), err
}
