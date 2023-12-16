package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"mime/multipart"
	"net/http"
	"regexp"
	"strings"

	"github.com/ag0st/taurus-challenge/api"
	"github.com/ag0st/taurus-challenge/config"
	"github.com/ag0st/taurus-challenge/errs"
	"github.com/ag0st/taurus-challenge/store"
	"github.com/google/uuid"
)

// Regexes for API path matching
var (
	FileRe       = regexp.MustCompile(`^/api/file/*$`)
	FileReWithID = regexp.MustCompile(`^/api/file/(.)+$`)
)

// Error declarations
var (
	ErrNotFound            = errs.New("unknown api path")
	ErrInvalidFormName     = errs.New("invalid form name in multipart/form-data")
	ErrInternalServerError = errs.New("internal server error")
)

type storeConfig struct {
	conn   *store.Connection
	bucket string
}

type handlerWithErrorFunc func(http.ResponseWriter, *http.Request) error

func (f handlerWithErrorFunc) ServeHTTP(w http.ResponseWriter, r *http.Request) error {
	return f(w, r)
}

func errorHandler(next handlerWithError) http.Handler {
	fn := func(w http.ResponseWriter, r *http.Request) {
		err := next.ServeHTTP(w, r)
		if err != nil {
			// Get the HTTP Code
			httpCode := http.StatusInternalServerError
			switch err {
			case ErrNotFound:
				httpCode = http.StatusNotFound
			}
			// print the error
			log.Printf("[ERROR] %v", err)

			err = errs.Collaps(errs.WrapPath(err, r.URL.Path))
			// Now marshal the error and write it

			// function to work with incoming errors
			manageErrorDuringHandling := func(err error, w http.ResponseWriter) {
				if err != nil {
					http.Error(w, "Unexpected error occurred", http.StatusInternalServerError)
				}
			}
			body, errMarshal := json.Marshal(err)
			manageErrorDuringHandling(errMarshal, w)
			w.WriteHeader(httpCode)
			_, errWrite := io.Copy(w, bytes.NewReader(body))
			manageErrorDuringHandling(errWrite, w)
		}
	}
	return http.HandlerFunc(fn)
}

// handlerWithError is a redefinition of a http.Handler that return an error if something happens.
type handlerWithError interface {
	// ServeHTTP mirror of the ServeHTTP inside the http.Handler but with error return instead of nothing.
	ServeHTTP(w http.ResponseWriter, r *http.Request) error
}

func httpHandler(sc *storeConfig) handlerWithError {
	fn := func(w http.ResponseWriter, r *http.Request) error {
		// Switch on the type of request
		switch {
		case r.Method == http.MethodGet && FileRe.MatchString(r.URL.Path): // List all files
			return handleListFile(sc, w, r)
		case r.Method == http.MethodPost && FileRe.MatchString(r.URL.Path): // Add a new file
			return handleAddFile(sc, w, r)
		case r.Method == http.MethodGet && FileReWithID.MatchString(r.URL.Path): // Get a file
			return handleGetFile(sc, w, r)
		default:
			return ErrNotFound
		}
	}
	return handlerWithErrorFunc(fn)
}

func handleListFile(sc *storeConfig, w http.ResponseWriter, r *http.Request) error {
	files, err := sc.conn.ListFiles(r.Context(), sc.bucket)
	if err != nil {
		return err
	}
	// Convert the files for return
	data, err := json.Marshal(api.FileItemFromMinio(files))
	if err != nil {
		return errs.WrapWithError(err, ErrInternalServerError)
	}
	_, err = w.Write(data)
	return errs.WrapWithError(err, ErrInternalServerError)
}

func handleAddFile(sc *storeConfig, w http.ResponseWriter, r *http.Request) error {
	// Get the multipart form data
	err := r.ParseMultipartForm(100 << 20) // 100 MiB
	if err != nil {
		return errs.WrapWithError(err, ErrInternalServerError)
	}
	reader, header, err := r.FormFile("file")
	if err != nil {
		return errs.WrapWithError(err, ErrInvalidFormName)
	}
	defer func(file multipart.File) {
		err := file.Close()
		if err != nil {
			fmt.Printf("cannot close the upload file: %v \n", err)
		}
	}(reader)

	objectName := ""
	switch {
	case r.FormValue("object_name") != "":
		objectName = r.FormValue("object_name")
	case header.Filename != "":
		objectName = header.Filename
	default:
		objectName = uuid.NewString()
	}
	filename := objectName
	if header.Filename != "" {
		filename = header.Filename
	}

	data, err := sc.conn.PushObject(r.Context(), reader,
		config.GetCurrent().Service().ChunkSize(),
		config.GetCurrent().Minio().Bucket(), objectName, filename,
		"application/octet-stream")
	if err != nil {
		return errs.WrapWithError(err, ErrInternalServerError)
	}
	// transform the data in json
	fus := api.FileUploadSuccess{
		ObjectName: data.Key,
		VersionID:  data.VersionID,
	}
	j, err := json.Marshal(fus)
	if err != nil {
		return errs.WrapWithError(err, ErrInternalServerError)
	}
	_, err = w.Write(j)
	return errs.WrapWithError(err, ErrInternalServerError)
}

func handleGetFile(sc *storeConfig, w http.ResponseWriter, r *http.Request) error {
	objectName := strings.TrimPrefix(r.URL.Path, "/api/file/")
	// retrieve the file
	reader, err := sc.conn.GetObject(r.Context(), config.GetCurrent().Minio().Bucket(), objectName)
	if err != nil {
		return errs.WrapWithError(err, ErrInternalServerError)
	}
	
	_, err = reader.WriteTo(w)
	if err != nil {
		return errs.WrapWithError(err, ErrInternalServerError)
	}
	// Put info in header that it is a file
	filename, err := reader.Filename()
	if err != nil {
		return errs.WrapWithError(err, ErrInternalServerError)
	}
	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment;filename=%s", filename))
	return nil
}

func init() {
	// Generate our config based on the config supplied
	// by the user in the flags
	cfgPath, err := config.ParseFlags()
	if err != nil {
		log.Fatal(err)
	}
	_, err = config.NewConfig(cfgPath)
	if err != nil {
		log.Fatal(err)
	}
}

func main() {
	// Create the connection to the database
	conn, err := store.Connect(
		config.GetCurrent().Minio().Endpoint(),
		config.GetCurrent().Minio().AccessKey(),
		config.GetCurrent().Minio().SecretKey(),
	)
	if err != nil {
		log.Fatal(err)
	}

	sc := &storeConfig{conn: conn, bucket: config.GetCurrent().Minio().Bucket()}

	// Create the server multiplexer
	mux := http.NewServeMux()

	handler := errorHandler(httpHandler(sc))
	mux.Handle(
		"/api/file",
		handler,
	)
	mux.Handle(
		"/api/file/",
		handler,
	)
	srv := &http.Server{
		Addr: config.GetCurrent().Service().Address(),
		Handler: mux,
	}

	log.Fatal(srv.ListenAndServe())
}
