package store

import (
	"context"
	"crypto/rand"
	"crypto/sha1"
	"crypto/sha256"
	"errors"
	"fmt"
	"hash/crc32"
	"io"
	"os"
	"reflect"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/minio/minio-go/v7"
)

type uploadStatus int

const (
	inProgress uploadStatus = iota
	completed
	aborted
)

type multipartUpload struct {
	status      uploadStatus
	parts       []minio.CompletePart
	partCounter int
	object      string
	totalSize   int64
}

type minioCoreMock struct {
	uploads map[string]*multipartUpload
}

func (c *minioCoreMock) PutObjectPart(ctx context.Context, bucket, object, uploadID string, partID int,
	data io.Reader, size int64, opts minio.PutObjectPartOptions,
) (minio.ObjectPart, error) {
	select {
	case <-ctx.Done():
		return minio.ObjectPart{}, ctx.Err()
	case <-time.After(time.Millisecond * 100):
		if mu, ok := c.uploads[uploadID]; ok {
			switch mu.status {
			case completed:
				return minio.ObjectPart{}, errors.New("upload already completed")
			case aborted:
				return minio.ObjectPart{}, errors.New("upload already aborted")
			case inProgress:
				// object has the right name
				if mu.object != object {
					return minio.ObjectPart{}, fmt.Errorf("object not valid, expected %s, got %s", mu.object, object)
				}
				// parts must be in right order
				if partID != mu.partCounter {
					return minio.ObjectPart{}, fmt.Errorf("wrong part id, expected: %d, got %d", mu.partCounter, partID)
				}
				// Check minio limitations
				if partID > 10_000 {
					return minio.ObjectPart{}, errors.New("number of part must be < 10_000")
				}
				// Read all must not create error
				d, err := io.ReadAll(data)
				if err != nil {
					return minio.ObjectPart{}, err
				}
				if int64(len(d)) != size {
					return minio.ObjectPart{}, fmt.Errorf("size of the part is not the same as data, expected %d (len data), got %d (size)", len(d), size)
				}

				mu.partCounter = mu.partCounter + 1
				mu.totalSize += size

				// calculate checksums
				crc_32 := string(crc32.NewIEEE().Sum(d))
				crc_32c := string(crc32.New(crc32.MakeTable(crc32.Castagnoli)).Sum(d))
				sha_1 := sha1.Sum(d)
				sha_256 := sha256.Sum256(d)

				op := minio.ObjectPart{PartNumber: partID, ETag: uuid.NewString(), LastModified: time.Now(), Size: size,
					ChecksumCRC32: crc_32, ChecksumCRC32C: crc_32c,
					ChecksumSHA1: string(sha_1[:]), ChecksumSHA256: string(sha_256[:])}
				cp := minio.CompletePart{
					PartNumber:     op.PartNumber,
					ETag:           op.ETag,
					ChecksumCRC32:  op.ChecksumCRC32,
					ChecksumCRC32C: op.ChecksumCRC32C,
					ChecksumSHA1:   op.ChecksumSHA1,
					ChecksumSHA256: op.ChecksumSHA256,
				}
				mu.parts = append(mu.parts, cp)
				return op, nil
			default:
				return minio.ObjectPart{}, errors.New("error in the mock, status does not exists")
			}
		} else {
			return minio.ObjectPart{}, errors.New("upload does not exists")
		}
	}
}

func (c *minioCoreMock) NewMultipartUpload(ctx context.Context, bucket, object string, opts minio.PutObjectOptions) (uploadID string, err error) {
	select {
	case <-ctx.Done():
		return "", ctx.Err()
	case <-time.After(time.Millisecond * 100):
		uploadID = uuid.NewString()
		c.uploads[uploadID] = &multipartUpload{status: inProgress, partCounter: 1, object: object}
		return uploadID, nil
	}
}

func (c *minioCoreMock) CompleteMultipartUpload(ctx context.Context, bucket, object, uploadID string, parts []minio.CompletePart, opts minio.PutObjectOptions) (minio.UploadInfo, error) {
	select {
	case <-ctx.Done():
		return minio.UploadInfo{}, ctx.Err()
	case <-time.After(time.Millisecond * 100):
		if mu, ok := c.uploads[uploadID]; ok {
			switch mu.status {
			case aborted:
				return minio.UploadInfo{}, errors.New("upload already aborted")
			case completed:
				return minio.UploadInfo{}, errors.New("upload already completed")
			case inProgress:

				if mu.object != object {
					return minio.UploadInfo{}, fmt.Errorf("object not valid, expected %s, got %s", mu.object, object)
				}
				// go through the parts and verify everything is correct
				if len(parts) != len(mu.parts) {
					return minio.UploadInfo{}, fmt.Errorf("wrong number of parts, expected %d, got %d", len(mu.parts), len(parts))
				}
				for i := 0; i < len(mu.parts); i++ {
					if !reflect.DeepEqual(mu.parts[i], parts[i]) {
						return minio.UploadInfo{}, fmt.Errorf("parts are not the same. expected %v, got %v", mu.parts[i], parts[i])
					}
				}
				mu.status = completed
				return minio.UploadInfo{Bucket: bucket, Key: object, ETag: uuid.NewString(), Size: mu.totalSize, LastModified: time.Now()}, nil
			default:
				return minio.UploadInfo{}, errors.New("error in mock, status does not exists")
			}
		} else {
			return minio.UploadInfo{}, errors.New("upload does not exists")
		}
	}
}
func (c *minioCoreMock) AbortMultipartUpload(ctx context.Context, bucket, object, uploadID string) error {
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-time.After(time.Millisecond * 100):
		if mu, ok := c.uploads[uploadID]; ok {
			switch mu.status {
			case aborted:
				return errors.New("upload already aborted")
			case completed:
				return errors.New("upload already completed")
			case inProgress:
				if mu.object != object {
					return fmt.Errorf("object not valid, expected %s, got %s", mu.object, object)
				}
				mu.status = aborted
				return nil
			default:
				return errors.New("error in mock, status does not exists")
			}
		} else {
			return errors.New("upload does not exists")
		}
	}
}

type minioClientMock struct {
	numberOfObjects int
	getObjectError  bool
	bucketExists    bool
}

func (c *minioClientMock) ListObjects(ctx context.Context, bucketName string, opts minio.ListObjectsOptions) <-chan minio.ObjectInfo {
	res := make(chan minio.ObjectInfo, 1)
	go func() {
		for i := 0; i < c.numberOfObjects; i++ {
			select {
			case <-ctx.Done():
				res <- minio.ObjectInfo{Err: ctx.Err()}
			default:
				time.Sleep(time.Millisecond * 100)
				res <- minio.ObjectInfo{
					Key:  "test.txt",
					Size: 1500,
				}
			}
		}
	}()
	return res
}

func (c *minioClientMock) GetObject(ctx context.Context, bucketName, objectName string, opts minio.GetObjectOptions) (*minio.Object, error) {
	if c.getObjectError {
		return nil, errors.New("Cannot give back the object")
	}
	return &minio.Object{}, nil

}
func (c *minioClientMock) BucketExists(ctx context.Context, bucketName string) (bool, error) {
	select {
	case <-ctx.Done():
		return false, ctx.Err()
	case <-time.After(time.Millisecond * 100):
		return c.bucketExists, nil
	}
}
func (c *minioClientMock) MakeBucket(ctx context.Context, bucketName string, opts minio.MakeBucketOptions) (err error) {
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-time.After(time.Millisecond * 100):
		if c.bucketExists {
			return errors.New("bucket already exists")
		} else {
			return nil
		}
	}
}
func (c *minioClientMock) PutObject(ctx context.Context, bucketName, objectName string, reader io.Reader, objectSize int64,
	opts minio.PutObjectOptions,
) (info minio.UploadInfo, err error) {
	select {
	case <-ctx.Done():
		return minio.UploadInfo{}, ctx.Err()
	case <-time.After(time.Millisecond * 100):
		if !c.bucketExists {
			return minio.UploadInfo{}, errors.New("bucket does not exist")
		} else {
			data, err := io.ReadAll(reader)
			if err != nil {
				return minio.UploadInfo{}, errors.New("error while reading the data")
			}
			if len(data) == 0 {
				return minio.UploadInfo{}, errors.New("no data given for the upload. Must not occur")
			}
			if len(data) != int(objectSize) {
				return minio.UploadInfo{}, errors.New("wrong size of the data")
			}
			if len(objectName) <= 0 {
				return minio.UploadInfo{}, errors.New("object name not given")
			}
		}
		return minio.UploadInfo{Bucket: bucketName, Key: objectName, Size: objectSize}, nil
	}
}

var (
	mockConn Connection
	upConf   uploadConfig
)

func TestMain(m *testing.M) {
	mockConn = Connection{core: &minioCoreMock{uploads: make(map[string]*multipartUpload, 100)}, client: &minioClientMock{
		numberOfObjects: 5,
		getObjectError:  false,
		bucketExists:    true,
	}}
	upConf = uploadConfig{bucketName: "test", objectName: "test.txt", contentType: "application/json"}
	exitCode := m.Run()
	os.Exit(exitCode)
}

func TestWriting(t *testing.T) {
	data := make([]byte, 50)
	_, err := rand.Read(data)
	if err != nil {
		t.Fatalf("test error, cannot create data array: %v", err)
	}
	testCases := []struct {
		chunckSize uint64
	}{
		{0}, {20}, {40}, {60},
	}

	for _, tc := range testCases {
		writer := newStoreWriter(context.Background(), tc.chunckSize, &mockConn, upConf)
		var n int64
		if tc.chunckSize == 0 {
			// Testing whole writer
			nn, err := writer.Write(data)
			if err != nil {
				t.Fatalf("unexpected error : %v", err)
			}
			n += int64(nn)
		} else {
			// write all
			for j := 0; j < len(data); j += int(tc.chunckSize) {
				remaining := min(tc.chunckSize, uint64(len(data)-j))
				nn, err := writer.Write(data[j : j+int(remaining)])
				if err != nil {
					t.Fatalf("unexpected error : %v", err)
				}
				n += int64(nn)
			}
		}

		if int64(len(data)) != n {
			t.Fatalf("number of writes is not right, expected %d, got %d", len(data), n)
		}
		err = writer.Close()
		if err != nil {
			t.Fatalf("unexpected error : %v", err)
		}
	}
}

func TestContextCancel(t *testing.T) {
	data := []byte("This is a test")
	finalFunctions := []func(storeWriterCloser, int){
		func(swc storeWriterCloser, chunkSize int) {
			_, err := swc.Write(data[0:min(len(data), chunkSize)])
			if err == nil {
				t.Fatal("expecting cancelation error")
			}
		},
		func(swc storeWriterCloser, chunkSize int) {
			err := swc.Close()
			if err == nil {
				t.Fatal("expecting cancelation error")
			}
		},
	}
	testCases := []struct {
		chunckSize int
		nbWrites   int
		finalFunction func(storeWriterCloser, int)
	}{
		{0, 0, finalFunctions[0]}, {2, 0, finalFunctions[0]}, {4, 0, finalFunctions[0]}, {15, 0, finalFunctions[0]},
		{0, 0, finalFunctions[1]}, {2, 0, finalFunctions[1]}, {4, 0, finalFunctions[1]}, {15, 0, finalFunctions[1]},
		{0, 1, finalFunctions[0]}, {2, 1, finalFunctions[0]}, {4, 1, finalFunctions[0]}, {15, 1, finalFunctions[0]},
		{0, 1, finalFunctions[1]}, {2, 1, finalFunctions[1]}, {4, 1, finalFunctions[1]}, {15, 1, finalFunctions[1]},
	}

	for _, tc := range testCases {
		ctx := context.Background()
		ctx, cancel := context.WithCancel(ctx)
		writer := newStoreWriter(ctx, uint64(tc.chunckSize), &mockConn, upConf)
		currNbWrites := 0
		for currNbWrites < tc.nbWrites {
			if tc.chunckSize == 0 && currNbWrites > 0 {
				continue
			}
			_, err := writer.Write(data[0:min(len(data), tc.chunckSize)])
			if err != nil {
				t.Fatalf("unexpected error : %v", err)
			}
			currNbWrites++
		}
		// now cancel the context
		cancel()
		// on first call on write, an error must occurs
		tc.finalFunction(writer, tc.chunckSize)
	}
}
