package encdec

import (
	"bytes"
	"crypto/cipher"
	"encoding/binary"
	"io"

	"github.com/ag0st/taurus-challenge/errs"
)

// Errors declarations
var (
	// ErrTooMuchChunk error is thrown when the number of chunks to encrypt a file is too
	// high.
	ErrTooMuchChunk error = errs.New("too much chunk produced. Max = 0xFFFF_FFFF")
	// ErrNoLastChunk error is thrown where it remains nothing to write to the underlying
	// writer at the closing stage.
	ErrNoLastChunk error = errs.New("no last chunk to write when closing the writer")
	// ErrWriterClosed error is thrown when trying to write to a writer that has already been
	// closed.
	ErrWriterClosed error = errs.New("writer already closed")
)

// newEncWriter creates the right type of writer regarding the data stored inside the header.
// It can create chunk writer or whole writer.
func NewEncWriter(key [keySize]byte, header header, dest io.Writer) (io.WriteCloser, error) {
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
// It is a io.WriteCloser.
// It first copies plaintext into its internal buffer and then encrypt it to push it into the writer.
// It keeps always a fully plaintext chunk inside its buffer for the closing stage
// where it set last chunk flag and push a last time into the underlying writer before closing.
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

func (ecw *encChunkWriter) Write(p []byte) (n int, err error) {
	if ecw.isClosed {
		return 0, ErrWriterClosed
	}
	// encrypt until we have read everything and that it remains enough for a last chunk
	for n < len(p) && len(p)-n > int(ecw.header.ChunkSize())-ecw.offset {
		// copy the maximum we can into our buffer
		// The buffer will be fulfilled regarding the condition of the for
		n += copy(ecw.buf[ecw.offset:], p[n:])
		ecw.offset = 0

		// Encrypt and push the data

		_, err := ecw.dest.Write(ecw.sealBuf(false))
		if err != nil {
			return 0, errs.Wrap(err, "cannot encrypt to the underlying writer")
		}
		ecw.currSeqNum++
		// check we did not passed the maximum seq number
		if ecw.currSeqNum == LAST_CHUNK_SEQ_NUM {
			return n, ErrTooMuchChunk
		}
	}
	// copy the last bits of data into the buffer
	bn := copy(ecw.buf[ecw.offset:], p[n:])
	ecw.offset += bn
	n += bn
	if n < len(p) {
		return n, io.ErrShortWrite
	}
	return
}

// Close closes the encChunkWriter by pushing the last chunk into the destination and close
// the destination if needed.
func (ecw *encChunkWriter) Close() error {
	ecw.isClosed = true
	if ecw.offset == 0 {
		return ErrNoLastChunk
	}
	_, err := ecw.dest.Write(ecw.sealBuf(true))
	if w, ok := ecw.dest.(io.WriteCloser); ok {
		return w.Close()
	}
	return err
}

// ReadFrom is the implementation of io.ReaderFrom for the encChunkWriter.
func (ecw *encChunkWriter) ReadFrom(r io.Reader) (n int64, err error) {
	if ecw.isClosed {
		return 0, ErrWriterClosed
	}
	// we read directly by chunk size and push it to the write method
	var buffer = make([]byte, ecw.header.ChunkSize())
	for {
		nn, err := r.Read(buffer[:])
		n += int64(nn)
		if err != nil {
			if err == io.EOF && nn == 0 {
				break
			} else if err != io.EOF {
				return n, err
			}
		}
		if _, err = ecw.Write(buffer[:nn]); err != nil {
			return n, err
		}
	}
	return n, err
}

// sealBuf seal the current plaintext buffer and return the encrypted result.
// This result can then be used to push into the underlying writer.
// isFinal must be only used once for the writer, it seals the final chunk.
// The user must assured that the plaintext buffer is not empty before calling this method.
func (ecw *encChunkWriter) sealBuf(isFinal bool) []byte {
	// 1. we need to build the IV for this chunk, embed the sequence number
	currentIV := ecw.header.IV()
	var destSize uint64 = seqNumSize + tagSizeByte
	currentSeqNum := ecw.currSeqNum
	if isFinal { // if is final chunk, put 0xFFFF_FFFF as sequence number
		currentSeqNum = LAST_CHUNK_SEQ_NUM
		destSize += uint64(ecw.offset)
		ecw.buf = ecw.buf[:ecw.offset] // limit the plaintext to write
	} else {
		destSize += ecw.header.ChunkSize()
	}
	binary.BigEndian.PutUint32(currentIV[ivHeaderSize-seqNumSize:], binary.BigEndian.Uint32(currentIV[ivHeaderSize-seqNumSize:])^currentSeqNum)
	// 2. Encrypt the data
	toPush := make([]byte, destSize)
	ecw.aesgcm.Seal(toPush[seqNumSize:seqNumSize], currentIV, ecw.buf, ecw.header.aad())
	// 3. Push the encrypted data to the writer
	binary.BigEndian.PutUint32(toPush[:seqNumSize], currentSeqNum)
	// 4. If it is the first write, append the header in the front
	if ecw.firstWrite {
		ecw.firstWrite = false
		return append(ecw.header[:], toPush...)
	}
	return toPush
}

// encWholeWriter is an io.WriteCloser. It encrypts the data as a whole.
// It first stores all the data into its internal buffer
// and then encrypt and push to the underlying writer when the Close is called.
type encWholeWriter struct {
	dest     io.Writer
	buf      []byte      // buffer to retain at least a chunk. Plaintext
	aesgcm   cipher.AEAD // The standard implementation of a cipher AEAD
	header   header      // Header that store the configuration of the encryption
	isClosed bool        // store if the writer has been closed
}

// newEncWholeWriter creates a new encWholeWriter
func newEncWholeWriter(h header, dest io.Writer, aesgcm cipher.AEAD) *encWholeWriter {
	return &encWholeWriter{
		dest:   dest,
		aesgcm: aesgcm,
		header: h,
		isClosed: false,
	}
}

// Write is the implemention of io.Writer of the encWholeWriter. It only stores data into its internal
// buffer. The encryption is done in the Close function.
func (eww *encWholeWriter) Write(p []byte) (n int, err error) {
	if eww.isClosed {
		return 0, ErrWriterClosed
	}
	// Add the data to the internal buffer
	eww.buf = append(eww.buf, p...)
	return len(p), nil
}

// Close is the implementation of the io.Closer function of a encWholeWriter. It Seals the data
// it has stored and push them into the underlying writer.
func (eww *encWholeWriter) Close() error {
	eww.isClosed = true
	// Seal the data and push it to the underlying writer
	toPush := eww.aesgcm.Seal(nil, eww.header.IV(), eww.buf, eww.header.aad())
	_, err := io.Copy(eww.dest, io.MultiReader(bytes.NewReader(eww.header[:]), bytes.NewReader(toPush)))
	if w, ok := eww.dest.(io.WriteCloser); ok {
		return w.Close()
	}
	return err
}

// ReadFrom is the implementation of io.ReaderFrom for the encWholeWriter
func (eww *encWholeWriter) ReadFrom(r io.Reader) (n int64, err error) {
	if eww.isClosed {
		return 0, ErrWriterClosed 
	}
	// It does not use the method write, instead it pushes directly
	// the whole data into the internal buffer of the encWholeWriter.
	// This way it uses 1 buffer less
	eww.buf, err = io.ReadAll(r)
	return int64(len(eww.buf)), err
}
