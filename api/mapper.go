package api

import (
	"github.com/minio/minio-go/v7"
)


type FileItem struct {
	ObjectName string `json:"object_name"`
	Size int64 `json:"size"`
}

type FileUploadSuccess struct {
	ObjectName string `json:"object_name"`
	VersionID string `json:"versionID"`
}

func FileItemFromMinio(list []minio.ObjectInfo) []FileItem {
	res := make([]FileItem, len(list))
	for i, it := range list {
		res[i] = FileItem{ObjectName: it.Key, Size: it.Size}
	}
	return res
}
