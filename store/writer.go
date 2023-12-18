package store

import (
	"bytes"
	"context"
	"io"

	"github.com/ag0st/taurus-challenge/errs"
	"github.com/minio/minio-go/v7"
)

// ErrWriterClosed error is thrown when trying to write to a closed writer
var ErrWriterClosed = errs.New("writer closed")

// storeWriterCloser is a storeWriter with the necessity of closing it.
type storeWriterCloser interface {
	io.Writer
	io.Closer
	// WaitOnFinished is a blocking method waiting on the upload to be done.
	WaitOnFinished() (minio.UploadInfo, error)
	// Cancel cancels the current upload.
	Cancel() error
}

// uploadConfig is a configuration given to a writer containing the informations
// on the minio service and the content type of its upload.
type uploadConfig struct {
	bucketName  string
	objectName  string
	contentType string
}

// uploadFinished structure contains the informations on a finished upload.
// When an uploadFinished is returned, the caller must always check the
// the error first.
type uploadFinished struct {
	info minio.UploadInfo
	err  error
}

// newStoreWriter creates the right type of storeWriter regarding the
// configuration.
func newStoreWriter(ctx context.Context, chunkSize uint64, core *minio.Core, config uploadConfig) storeWriterCloser {
	if chunkSize > 0 {
		return newChunckWriter(ctx, chunkSize, core, config)
	} else {
		return newAutoWriter(ctx, core, config)
	}
}

// storeChunkWriter is an implementation of a storeWriterCloser that
// upload each write as a chunk to the minio bucket.
// Each writes are writen as a chunk.
// It uses the minio implementation of MultiPart upload and is constraint
// to its limitations.
type storeChunkWriter struct {
	bucketName  string               // destination bucket
	objectName  string               // name of the object to upload
	contentType string               // content type of the object
	chunkSize   uint64               // size of the chunks
	parts       []minio.CompletePart // stores informations on all the chunks that have been uploaded.
	cnt         int                  // cnt is an internal counter to assign identifier to each chunk
	uploadId    string               // the current upload id for the mulitpart upload.
	firstWrite  bool                 // store if the writer already uploaded some chunks
	isClosed    bool                 // state of the writer (closed of not)
	ctx         context.Context      // current context for cancelation
	fchan       chan uploadFinished  // fchan is a channel to indicate when the upload is finished
	core        *minio.Core          // the minio core to create new upload
}

// newChunkWriter creates a new storeWriterCloser implementing the chunk technique.
func newChunckWriter(ctx context.Context, chunkSize uint64, core *minio.Core, config uploadConfig) storeWriterCloser {
	return &storeChunkWriter{
		bucketName:  config.bucketName,
		objectName:  config.objectName,
		contentType: config.contentType,
		firstWrite:  true,
		ctx:         ctx,
		chunkSize:   chunkSize,
		cnt:         1, // counter must begin at 1 (see MinIo documentation)
		isClosed:    false,
		fchan:       make(chan uploadFinished, 1), // do not block on write
		core:        core,
	}
}

// Write writes a chunk on minio. The size of p must be of size of the chunk.
func (scw *storeChunkWriter) Write(p []byte) (n int, err error) {
	if scw.isClosed {
		return 0, ErrWriterClosed
	}
	// If it is the first write, we need to instanciate a new multipart upload
	if scw.firstWrite {
		scw.uploadId, err = scw.core.NewMultipartUpload(scw.ctx, scw.bucketName, scw.objectName, minio.PutObjectOptions{ContentType: scw.contentType})
		if err != nil {
			return 0, err
		}
		scw.firstWrite = false
	}
	select {
	case <-scw.ctx.Done():
		scw.Cancel()
		return 0, scw.ctx.Err()
	default:
		op, err := scw.core.PutObjectPart(scw.ctx, scw.bucketName,
			scw.objectName, scw.uploadId,
			scw.cnt, bytes.NewReader(p), int64(len(p)),
			minio.PutObjectPartOptions{})
		if err != nil {
			return 0, err
		}
		cp := minio.CompletePart{
			PartNumber:     op.PartNumber,
			ETag:           op.ETag,
			ChecksumCRC32:  op.ChecksumCRC32,
			ChecksumCRC32C: op.ChecksumCRC32C,
			ChecksumSHA1:   op.ChecksumSHA1,
			ChecksumSHA256: op.ChecksumSHA256,
		}
		scw.parts = append(scw.parts, cp)
		scw.cnt++
		return len(p), nil
	}
}

// Close is the implementation of io.Closer. It finalize the upload on minio.
func (scw *storeChunkWriter) Close() error {
	// close the multipart upload
	scw.isClosed = true
	go func() {
		info, err := scw.core.CompleteMultipartUpload(scw.ctx, scw.bucketName, scw.objectName, scw.uploadId, scw.parts, minio.PutObjectOptions{})
		scw.fchan <- uploadFinished{info, err}
	}()
	return nil
}

func (scw *storeChunkWriter) WaitOnFinished() (minio.UploadInfo, error) {
	res := <-scw.fchan
	return res.info, res.err
}

func (scw *storeChunkWriter) Cancel() error {
	scw.isClosed = true
	// if not finished, we need to abort the current upload
	return scw.core.AbortMultipartUpload(context.Background(), scw.bucketName, scw.objectName, scw.uploadId)
}

// storeAutoWriter is a storeWriter that stores the data written to it inside a buffer
// and upload the whole data as one on close.
type storeAutoWriter struct {
	bucketName  string
	objectName  string
	contentType string
	isClosed    bool
	ctx         context.Context
	fchan       chan uploadFinished
	core        *minio.Core
	buf         []byte
}

// newAutoWriter creates a new auto writer.
func newAutoWriter(ctx context.Context, core *minio.Core, config uploadConfig) storeWriterCloser {
	return &storeAutoWriter{
		bucketName:  config.bucketName,
		objectName:  config.objectName,
		contentType: config.contentType,
		isClosed:    false,
		ctx:         ctx,
		fchan:       make(chan uploadFinished, 1), // do not block on write
		core:        core,
	}
}

// Write is the implementation of the io.Writer interface.
func (saw *storeAutoWriter) Write(p []byte) (n int, err error) {
	if saw.isClosed {
		return 0, ErrWriterClosed
	}
	saw.buf = append(saw.buf, p...)
	return len(p), nil

}

func (saw *storeAutoWriter) WaitOnFinished() (minio.UploadInfo, error) {
	res := <-saw.fchan
	return res.info, res.err
}

func (saw *storeAutoWriter) Cancel() error {
	saw.isClosed = true
	return nil
}
// Close is the implementation of io.Closer
// It uploads the whole buffered data as one to the minio bucket
func (saw *storeAutoWriter) Close() error {
	saw.isClosed = true
	info, err := saw.core.Client.PutObject(saw.ctx, saw.bucketName,
		saw.objectName, bytes.NewReader(saw.buf), int64(len(saw.buf)), minio.PutObjectOptions{
			PartSize:         uint64(len(saw.buf)),
			DisableMultipart: true,
		})
	// post to the channel if somebody is waiting
	saw.fchan <- uploadFinished{info, err}
	return err
}
