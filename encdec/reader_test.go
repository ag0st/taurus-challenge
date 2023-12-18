package encdec

import (
	"bytes"
	"encoding/hex"
	"io"
	"testing"
)

// TestDecReaderNoRead test that a reader reader an error when trying to get
// info when no first read has been made
func TestDecReaderNoRead(t *testing.T) {
	reader, err := NewDecReader(testKey, bytes.NewBuffer([]byte{}))
	if err != nil {
		t.Error(err)
	}
	_, err = reader.Filename()
	if err != ErrNoFirstRead {
		t.Fatalf("Expecting ErrNoFirst, got: %v", err)
	}
}

// TestDecReaderDecryption test the decryption of multiple format and
// error in encrypted data.
func TestDecReaderDecryption(t *testing.T) {
	data, plaintext := testData()
	filename := "test.txt"
	for i := 0; i < len(data); i++ {
		reader, err := NewDecReader(testKey, bytes.NewBuffer(data[i]))
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		d, err := io.ReadAll(reader)
		if i <= 1 {
			if !bytes.Equal(d, plaintext) {
				t.Fatalf("decryption result is not right. expected %s, got %s", plaintext, d)
			}
			fn, err := reader.Filename()
			if err != nil {
				t.Fatalf("unable to extract filename: %v", err)
			}
			if fn != filename {
				t.Fatalf("filenames do not match. expected %s, got %s", filename, fn)
			}
		} else {
			// here expecting errors
			if err == nil {
				t.Fatal("expected error, got nil")
			}
		}
	}
}

// TestReaderEOF tests that the reader implementations delivers what is 
// described for an io.Reader.
func TestReaderEOF(t *testing.T) {
	// data[0] = whole file, data[1] = chunk
	data, plaintext := testData()
	data = data[:2]
	for i := 0; i < len(data); i++ {
		reader, err := NewDecReader(testKey, bytes.NewReader(data[i]))
		if err != nil {
			t.Fatalf("unexpected error, got %v", err)
		}
		// read zero length
		dest := []byte{}
		n, err := reader.Read(dest)
		if n != 0 || err != nil {
			t.Fatalf("expected n=0 and err=nil, got n=%d and err=%v", n, err)
		}

		// read smaller size
		sizeFirstRead := len(plaintext) / 2
		dest = make([]byte, sizeFirstRead)
		n, err = reader.Read(dest)
		if n != sizeFirstRead || err != nil {
			t.Fatalf("expected n=%d and err=nil, got n=%d and err=%v",sizeFirstRead, n, err)
		}
		// Read exactly all the data
		remaining := len(plaintext) - sizeFirstRead
		dest = append(dest, make([]byte, remaining)...)
		n, err = reader.Read(dest[sizeFirstRead:])
		if n != remaining || (err != nil && err != io.EOF) {
			t.Fatalf("expected n=%d and err=nil or err=io.EOF, got n=%d and err=%v",remaining, n, err)
		}

		// Test EOF
		dest = make([]byte, 5)
		n, err = reader.Read(dest)
		if n != 0 || err != io.EOF {
			t.Fatalf("expected n=%d and err=nil or err=io.EOF, got n=%d and err=%v",0, n, err)
		}
	}
}

func testData() ([][]byte, []byte) {
	// All the data are an encryption of the text: "This is a test"
	data := []string {
		// Whole file encryption
		"746573742e7478740000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000a9e6f5f672e7b55966392d6e2ca2b84b636f85e06ddab13d889765b2e1c28f7e37b1b179dc7f13f2adbc",
		// One byte chunk encryption
		"746573742e7478740000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001d9237413b03fb76bdc0476810000000049eaefc47b9c3959873354eb1140bca3e8000000019ab019687a1da50ccd4a362b43ab9232850000000279a57fb2d62cdd8510662fc4ef8105600100000003dbd875fd9900be39ae1a2571e66968beec00000004314328e01658876a217846c66162b758a1000000050556a10ad41ea3a1d5dcb4cc731fb54548000000068d713b687f745578e01324db4618b56ae00000000787862e73f198fe7d4f81f0214de411634c0000000803cdc4287f4951db332ae5cfdd15e5871c00000009df0fcb207c3986ec381b3e33042bed17fa0000000aced926f329de6503b47db5b92b7f86ef500000000b4f4c4f7ee467e458de2dd18b7dd121356f0000000c404c0e35ebf86cb4d5b1fe9c45f53ad425ffffffffea8209ac0678fef72b79ec8eb1fcdce155",
		// Whole file encryption with bad tag
		"746573742e7478740000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000a9e6f5f672e7b55966392d6e2ca2b84b636f85e06ddab13d889765b2e1c28f7e37b1b179dc7f13f2adbd",
		// Whole file encryption with bad iv
		"746573742e7478740000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000a9e6f5f572e7b55966392d6e2ca2b84b636f85e06ddab13d889765b2e1c28f7e37b1b179dc7f13f2adbc",
		// Whole file encryption with not authenticated additional data
		"746573742e7478745200000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000a9e6f5f672e7b55966392d6e2ca2b84b636f85e06ddab13d889765b2e1c28f7e37b1b179dc7f13f2adbc",
		// Two bytes chunk encryption with error in sequence number
		"746573742e7478740000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000002bcc3470be9962e1d809d94f200000000cf38f41d4c5bcdfe37187e619fe5e4505dfa00000001d813e4e8a3e78296a8ef24fc11584cbe56290000000293ce0f327c32355406d78dd91e2d3050bb1900000003c4fb6863c36701baf1cc4fc90a2766925ddd00000003bb0291bfad0db88b742b8c5e3adeb9b67eed0000000551c7b09ee77b336ffe276fab3e170ff29f79ffffffff948ccd5ef7b27487a36fba59cc8959b50e1f",
		// Three bytes chunk encryption with bad tag
		"746573742e74787400000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000032f16c5810555c0818163720000000000d410f14d2a8c41f1fc4d9ce33524d4e7c959ea000000014617c3bbb530e5b5d49074e7c67c614c5e454b00000002370bef4f1b7a2cc5b292ca081833e05df17c4e00000003795b3fb44fe332a8b1ff2d8742966f8d45a846ffffffff2d3a72b8be03231eb053ed9161416547ccc6",
		// Four bytes chunk encryption with wrong end sequence number
		"746573742e7478740000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000004e52efc8ef1e57c65f93fbbdf000000007f62669a4b6007debdb35c73746465ead6778709000000017a422fea8c32b06e4b9b4421ad1b26587ff9dfd800000002d0df5ea8fedfee8fe558c243551877b01b23e059000000037d22710da8a1dd756c53abe26610ec5b04c4",
		// Five bytes chunk encryption with not authenticated additional data
		"746573742e747874730000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000530ad25f98ce1ce27b138df68000000003c0713769f3e4b63bbfc1dd3b786e7bf81e447b3ff00000001cb385f965c43fa442653d7af424b0e1b74b1760626ffffffff4ba299495a1b62a6a56666c71c0033dbe3d34d44",
	}
	var res [][]byte
	for i := 0; i < len(data); i++ {
		e, err := hex.DecodeString(data[i])
		if err != nil {
			panic(err)
		}
		res = append(res, e)
	}
	return res, []byte("This is a test")
}