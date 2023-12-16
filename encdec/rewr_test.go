package encdec

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"io"
	"testing"
)

func TestReaderWriter(t *testing.T) {
	key, err := hex.DecodeString("000102030405060708090A0B0C0D0E0FF0E0D0C0B0A090807060504030201000")
	if err != nil {
		panic(err)
	}
	// create the key of 32 bit length
	key1 := [keySize]byte(key)

	toEncrypt := []byte("CECI EST un Tes")
	chunkSize := 5
	h := header{}
	h.SetChunkSize(uint64(chunkSize))
	iv, err := generateIV()
	if err != nil {
		panic("Cannot generate the IV")
	}
	h.SetIV(iv)
	filename := "test.txt"
	h.SetFilename(filename)

	// Buffer to write encrypted data to
	buff := bytes.NewBuffer([]byte{})
	ew, err := NewEncWriter(key1, h, buff)
	if err != nil {
		panic(err)
	}
	_, err = ew.Write(toEncrypt)
	if err != nil {
		panic(err)
	}
	err = ew.Close()
	if err != nil {
		panic(err)
	}
	fmt.Printf("Encrypted size: %d, expected: %d \n", buff.Len(),
		headerSizeByte+(len(toEncrypt)/chunkSize)*(chunkSize+seqNumSize+tagSizeByte))

	// Now read from it
	dr, err := NewDecReader(key1, buff)
	if err != nil {
		panic(err)
	}
	res, err := io.ReadAll(dr)
	if err != nil {
		panic(err)
	}

	if string(res) != string(toEncrypt) {
		t.Fail()
	}
	if r, ok := dr.(*decModeReader); ok {
		fn, err := r.Filename()
		if err != nil {
			panic(err)
		}
		if fn != filename {
			t.Fail()
		}
	} else {
		panic("cannot convert reader to decReader")
	}
}

func TestReadToWriteTo(t *testing.T) {
	key, err := hex.DecodeString("000102030405060708090A0B0C0D0E0FF0E0D0C0B0A090807060504030201000")
	if err != nil {
		panic(err)
	}
	// create the key of 32 bit length
	key1 := [keySize]byte(key)

	toEncrypt := []byte("CECI EST un Test")
	chunkSize := 5
	h := header{}
	h.SetChunkSize(uint64(chunkSize))
	iv, err := generateIV()
	if err != nil {
		panic("Cannot generate the IV")
	}
	h.SetIV(iv)
	filename := "test.txt"
	h.SetFilename(filename)

	temp := bytes.NewBuffer([]byte{})
	dest := bytes.NewBuffer([]byte{})
	src := bytes.NewBuffer(toEncrypt)
	ew, err := NewEncWriter(key1, h, temp)
	if err != nil {
		t.Fatal(err)
	}
	dr, err := NewDecReader(key1, temp)
	if err != nil {
		t.Fatal(err)
	}
	io.Copy(ew, src)
	ew.Close()
	io.Copy(dest, dr)
	

	if string(dest.String()) != string(toEncrypt) {
		t.Fail()
	}
}
