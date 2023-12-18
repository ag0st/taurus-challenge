package encdec

import (
	"bytes"
	"testing"
)

// TestWriteToClosedWriter test if the writer returns an error when trying to
// write after closing it
func TestWriteToClosedWriter(t *testing.T) {
	dest := bytes.NewBuffer([]byte{})

	// testing both writers
	for i := 0; i < 2; i++ {
		w, err := NewEncWriter(testKey, NewHeader(uint64(i), "test.txt"), dest)
		if err != nil {
			t.Fatalf("Unexpected error for writer %d : %v", i, err)
		}
		// close the writer
		err = w.Close()
		if err != nil {
			t.Fatalf("Unexpected error for writer %d : %v", i, err)
		}
		_, err = w.Write([]byte{0x0, 0x1})
		if err != ErrWriterClosed {
			t.Fatalf("expected ErrWriterClosed for writer %d, got: %v", i, err)
		}
	}
}

func TestBytesWritten(t *testing.T) {
	data := []byte("This is a test")
	// testing both writers
	for i := 0; i < len(data)*2; i++ {
		dest := bytes.NewBuffer([]byte{})
		w, err := NewEncWriter(testKey, NewHeader(uint64(i), "test.txt"), dest)
		if err != nil {
			t.Fatalf("Unexpected error for writer with chunk size %d : %v", i, err)
		}

		// write to the writer
		n, err := w.Write(data)
		if err != nil {
			t.Fatalf("Unexpected error for writer with chunk size %d : %v", i, err)
		}
		if n != len(data) {
			t.Fatalf("expected %d bytes writen for writer with chunk size %d, got : %d", len(data), i, n)
		}

		err = w.Close()
		if err != nil {
			t.Fatalf("Unexpected error for writer witch chunksize %d : %v", i, err)
		}

		// check the data inside the destination buffer
		nn := len(dest.Bytes())
		size := headerSizeByte
		if i > 0 { // for chunk writer
			size += (len(data) / i) * (i + seqNumSize + tagSizeByte)
			if rest := len(data) % i; rest > 0 {
				size += rest + seqNumSize + tagSizeByte
			}
		} else {
			size += len(data) + tagSizeByte
		}
		if nn != size {
			t.Fatalf("expecting total size of %d for writer with chunksize %d, got %d", size, i, nn)
		}
	}
}

