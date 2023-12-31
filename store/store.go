package store

import (
	"context"
	"io"

	"github.com/ag0st/taurus-challenge/config"
	"github.com/ag0st/taurus-challenge/encdec"
	"github.com/ag0st/taurus-challenge/errs"
	"github.com/minio/minio-go/v7"
	"github.com/minio/minio-go/v7/pkg/credentials"
)

// errors declaration
var (
	// ErrWrongChunkSize error is thrown when the chunk size given does not respect
	// the limitations.
	ErrWrongChunkSize = errs.New("wrong chunk size, must be : 5<<20 <= chunkSize <= 5<<30 or equal to 0")
)

// Client represent the essentials methods needed from minio.Client for the store to work
// Used for dependency injection (mocking)
type Client interface {
	ListObjects(ctx context.Context, bucketName string, opts minio.ListObjectsOptions) <-chan minio.ObjectInfo
	GetObject(ctx context.Context, bucketName, objectName string, opts minio.GetObjectOptions) (*minio.Object, error)
	BucketExists(ctx context.Context, bucketName string) (bool, error)
	MakeBucket(ctx context.Context, bucketName string, opts minio.MakeBucketOptions) (err error)
	PutObject(ctx context.Context, bucketName, objectName string, reader io.Reader, objectSize int64,
		opts minio.PutObjectOptions,
	) (info minio.UploadInfo, err error)
}

// Core represent the essentials methods needed from a minio.Core for the store to work.
// Used for dependency injection (mocking)
type Core interface {
	PutObjectPart(ctx context.Context, bucket, object, uploadID string, partID int,
		data io.Reader, size int64, opts minio.PutObjectPartOptions,
	) (minio.ObjectPart, error)
	NewMultipartUpload(ctx context.Context, bucket, object string, opts minio.PutObjectOptions) (uploadID string, err error)
	CompleteMultipartUpload(ctx context.Context, bucket, object, uploadID string, parts []minio.CompletePart, opts minio.PutObjectOptions) (minio.UploadInfo, error)
	AbortMultipartUpload(ctx context.Context, bucket, object, uploadID string) error
}

// Connection is the minio core used across the package to communicate with the minio server.
type Connection struct {
	client Client
	core   Core
}

// Connect creates a new connection to the server.
func Connect(endpoint, accessKey, secretKey string) (*Connection, error) {
	var err error
	core, err := minio.NewCore(endpoint, &minio.Options{
		Creds: credentials.NewStaticV4(accessKey, secretKey, ""),
	})
	if err != nil {
		return nil, err
	}
	return &Connection{core: core, client: core.Client}, nil
}

// PushObject pushes the data contained in the reader into the minio bucket.
// It will encrypt it before pushing the data into MinIo.
// If chunkSize > 0 then the file is encrypted in chunk and each chunk are
// push in a multipart upload.
// PRE:  5<<20 <= chunkSize <= 5<<30 || chunkSize = 0 (limitation of MinIo)
// PRE: len(data)/chunkSize < 10'000 (limitation of MinIo)
// MinIo Limitations:
// Description here : https://min.io/docs/minio/linux/operations/concepts/thresholds.html
// Min of 5MiB for chunk is here : https://github.com/minio/minio/blob/b3314e97a64a42d22ba5b939917939d72a28c97d/cmd/utils.go#L273C12-L273C12
// Max of 10'000 chunk is here : https://github.com/minio/minio/blob/b3314e97a64a42d22ba5b939917939d72a28c97d/cmd/utils.go#L277
func (c *Connection) PushObject(ctx context.Context, r io.Reader, chunkSize uint64, bucketname, objectName, filename, contentType string) (minio.UploadInfo, error) {
	// precondition
	if chunkSize != 0 && (chunkSize < 5<<20 || chunkSize > 5<<30) {
		return minio.UploadInfo{}, ErrWrongChunkSize
	}
	// create a new store writer and wrap it with en encrypt writer.
	sw := newStoreWriter(ctx, chunkSize, c,
		uploadConfig{bucketName: bucketname, objectName: objectName, contentType: contentType})
	h := encdec.NewHeader(chunkSize, filename)
	ew, err := encdec.NewEncWriter(config.GetCurrent().Service().AESKey(), h, sw)
	if err != nil {
		return minio.UploadInfo{}, nil
	}
	// Now, we have to copy the content of the reader to the writer.
	// We use the ReaderFrom interface of the encWriter to do so

	// Here we need to check on the context. If it is cancelled,
	// the storeWriter will cancel itself and then returning an error
	// on new writes.
	writeData := func() chan error {
		errc := make(chan error)
		go func() {
			if wr, ok := ew.(io.ReaderFrom); ok {
				_, err = wr.ReadFrom(r)
			} else {
				_, err = io.Copy(ew, r)
			}
			errc <- err
		}()
		return errc
	}

	select {
	case <-ctx.Done():
		return minio.UploadInfo{}, nil
	case err := <-writeData():
		if err != nil {
			// need to properly close the store writer
			cancelErr := errs.Wrap(sw.Cancel(), "error during cancel")
			return minio.UploadInfo{}, errs.WrapWithError(err, cancelErr)
		}
	}

	// now close the writer to finish the transaction
	ew.Close()

	return sw.WaitOnFinished()
}

// ListFiles list all the files in the bucket, without versionning
func (c *Connection) ListFiles(ctx context.Context, bucketname string) (objects []minio.ObjectInfo, err error) {
	for ob := range c.client.ListObjects(ctx, bucketname, minio.ListObjectsOptions{}) {
		if ob.Err != nil {
			if ob.Err == ctx.Err() { // we reached the final object, ctx canceled
				return nil, ctx.Err()
			} else {
				// store the last error, must continue to drain
				err = ob.Err
			}
		} else {
			objects = append(objects, ob)
		}
	}
	return objects, err
}

// GetObject returns an object. If the object doesn't exist, the result will be pushed into
// the object structure via read.
func (c *Connection) GetObject(ctx context.Context, bucketname, objectName string) (encdec.Reader, error) {
	obj, err := c.client.GetObject(ctx, bucketname, objectName, minio.GetObjectOptions{})
	if err != nil {
		return nil, err
	}
	// create a decryption reader and return this reader
	return encdec.NewDecReader(config.GetCurrent().Service().AESKey(), obj)
}

// CreateBucketIfNotExists creates a new bucket if it does not already exists on the server.
func (c *Connection) CreateBucketIfNotExists(ctx context.Context, bucketName string) error {
	exists, err := c.client.BucketExists(ctx, bucketName)
	if err != nil {
		return err
	}
	if !exists {
		return c.client.MakeBucket(ctx, bucketName, minio.MakeBucketOptions{})
	}
	return nil
}
