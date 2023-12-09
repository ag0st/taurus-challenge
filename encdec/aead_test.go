package encdec

import (
	"bytes"
	"context"
	"encoding/hex"
	"io"
	"os"
	"testing"
)


func TestEncrypt(t *testing.T) {
	key, err := hex.DecodeString("000102030405060708090A0B0C0D0E0FF0E0D0C0B0A090807060504030201000")
	if err != nil {
		panic(err)
	}
	ctx := context.Background()
	ctx = context.WithValue(ctx, "Key", [32]byte(key))

	toEncrypt := []byte("CECI EST un Test")

	reader := bytes.NewReader(toEncrypt)

	pr, pw := io.Pipe()

	decFinished := make(chan struct{})
	buffer := bytes.NewBuffer([]byte{})
	go func (ctx context.Context, w io.Writer)  {
		if err := Decrypt(ctx, w, pr); err != nil {
			panic(err)
		}
		decFinished <- struct{}{}
	}(ctx, io.MultiWriter(buffer, os.Stdout))

	buff := bytes.NewBuffer([]byte{})
	err = Encrypt(ctx, io.MultiWriter(pw, buff), reader)
	pw.CloseWithError(err)

	if err != nil {
		panic(err)
	}
	<-decFinished
	if buffer.String() != string(toEncrypt) {
		t.Fail()
	}
}