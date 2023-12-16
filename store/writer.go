package store

import (
	"bytes"
	"context"
	"io"

	"github.com/ag0st/taurus-challenge/errs"
	"github.com/minio/minio-go/v7"
)

var ErrWriterClosed = errs.New("writer closed")

type storeWriter interface {
	io.Writer
	WaitOnFinished() (minio.UploadInfo, error)
	Cancel() error
}

type storeWriterCloser interface {
	storeWriter
	io.Closer
}

type uploadConfig struct {
	bucketName  string
	objectName  string
	contentType string
}

type uploadFinished struct {
	info minio.UploadInfo
	err  error
}

func newStoreWriter(ctx context.Context, chunkSize uint64, core *minio.Core, config uploadConfig) storeWriter {
	if chunkSize > 0 {
		return newChunckWriter(ctx, chunkSize, core, config)
	} else {
		return newAutoWriter(ctx, core, config)
	}
}

type storeChunkWriter struct {
	bucketName  string
	objectName  string
	contentType string
	chunkSize   uint64
	parts       []minio.CompletePart
	cnt         int
	uploadId    string
	firstWrite  bool
	isFinished  bool
	ctx         context.Context
	fchan       chan uploadFinished
	core        *minio.Core
}

func newChunckWriter(ctx context.Context, chunkSize uint64, core *minio.Core, config uploadConfig) storeWriterCloser {
	return &storeChunkWriter{
		bucketName:  config.bucketName,
		objectName:  config.objectName,
		contentType: config.contentType,
		firstWrite:  true,
		ctx:         ctx,
		chunkSize:   chunkSize,
		cnt:         1, // counter must begin at 1 (see MinIo documentation)
		isFinished:  false,
		fchan:       make(chan uploadFinished, 1), // do not block on write
		core:        core,
	}
}

// Write writes a chunk on minio. The size of p must be of size of the chunk.
func (scw *storeChunkWriter) Write(p []byte) (n int, err error) {
	if scw.isFinished {
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

func (scw *storeChunkWriter) Close() error {
	// close the multipart upload
	scw.isFinished = true
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
	scw.isFinished = true
	// if not finished, we need to abort the current upload
	return scw.core.AbortMultipartUpload(context.Background(), scw.bucketName, scw.objectName, scw.uploadId)
}

type storeAutoWriter struct {
	bucketName  string
	objectName  string
	contentType string
	isFinished  bool
	ctx         context.Context
	uploadInfo  minio.UploadInfo
	fchan       chan uploadFinished
	core        *minio.Core
}

func newAutoWriter(ctx context.Context, core *minio.Core, config uploadConfig) storeWriter {
	return &storeChunkWriter{
		bucketName:  config.bucketName,
		objectName:  config.objectName,
		contentType: config.contentType,
		isFinished:  false,
		ctx:         ctx,
		fchan:       make(chan uploadFinished, 1), // do not block on write
		core:        core,
	}
}

func (saw *storeAutoWriter) Write(p []byte) (n int, err error) {
	if saw.isFinished {
		return 0, ErrWriterClosed
	}
	info, err := saw.core.Client.PutObject(saw.ctx, saw.bucketName,
		saw.objectName, bytes.NewReader(p), int64(len(p)), minio.PutObjectOptions{
			PartSize:         uint64(len(p)),
			DisableMultipart: true,
		})
	// post to the channel if somebody is waiting
	saw.fchan <- uploadFinished{info, err}
	// it makes only one upload
	saw.isFinished = true
	if err != nil {
		return 0, err
	}
	return len(p), nil
}

func (saw *storeAutoWriter) WaitOnFinished() (minio.UploadInfo, error) {
	res := <-saw.fchan
	return res.info, res.err
}

func (saw *storeAutoWriter) Cancel() error {
	saw.isFinished = true
	return nil
}
