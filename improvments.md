## Form data
Instead of using ParsMultipartForm, we can imagine something working in a more
_streamy way_. We do not load the entire file, but instead we read part by part
until we find the filename and the form entry name.
A possible attack must be taken in consideration :
- The client can push a very large amount of data without puting the filename or the form name at the beginning.

To prevent this, it must read from until reaching an upper limit in memory.
If this limit is reached, it creates a temp file and push into it on disk with again another limit.

Here the beginning of an implementation : 
```go
var	(
    ErrMalformedFormData = errs.New("cannot read the Content-Type attribute")
    ErrNoBoundaryInContentType = errors.New("expected boundary value in Content-Type multipart/form-data")
    ErrNotMultipartFormData    = errors.New("bad mediatype, wanted: multipart/form-data")

)

func handleAddFile(sc *storeConfig, w http.ResponseWriter, r *http.Request) error {
	// Get the multipart as a stream
	contentType, ctparams, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err != nil {
		return ErrMalformedFormData
	}
	if contentType != "multipart/form-data" {
		return ErrNotMultipartFormData
	}
	boundary, ok := ctparams["boundary"]
	if !ok {
		return ErrNoBoundaryInContentType
	}

	// In multipart form data, every form name (entry) come in sequence.
	// We can then read data until we find the form name and when found,
	// we know which entry we are reading. If the form name is "file", we are reading
	// the file.

	// create a io.Pipe to write the stream we read from the multipart reader
	// into it and give the reader end to the encryption. We must wait until we
	// find the form name and filename in part to begin writting
	pr, pw := io.Pipe()

	// buffer to store the data until we find the form name

	// to protect against attack with big file and form name at the end (which would)
	// force us to store a too much in memory), we put a limit on which we begin to write
	// into a file.
	maxInMemoryLimit := 100 << 20 // 100MiB

	filename := ""

	reader := multipart.NewReader(r.Body, boundary)

	resChan := make(chan minio.UploadInfo, 1)

	// Read until we know the name of the form or the filepath
	for {
		part, err := reader.NextPart()
		if err == io.EOF {
			break
		}
		// Check the form name
		switch part.FormName() {
		case "file":
			// try to get the filename if not already found
			if filename != "" {
				// push to the writer
				data, err := io.ReadAll(part)
				if err != nil {
					return ErrMalformedFormData
				}
				pw.Write(data)
			} else if part.FileName() != "" {
				// We found the name of the file
				filename = part.FileName()
				// push what we read in our buffer and push everything into the
				// pipe writer.
				// Then we can launch the store
				go func(ctx context.Context, filename string) {
					data, err := sc.conn.PushObject(ctx, pr,
						config.GetCurrent().Service().ChunkSize(),
						config.GetCurrent().Minio().Bucket(), filename, filename, "application/octet-stream")
					pr.CloseWithError(err)
					resChan <- data
				}(r.Context(), filename)
			} else {
				// we don't know yet the filename, cannot launch the execution, push
				// to the buffer.
				
			}
		case "":
			// We don't know yet

		default:
			// unknown form name
			return ErrInvalidFormName
		}

	}
	err = pw.Close()
	if err != nil {
		return err
	}

	// wait on the data
	data := <-resChan
	// transform the data in json
	fus := api.FileUploadSuccess{
		ObjectName: data.Key,
		VersionID:  data.VersionID,
	}
	j, err := json.Marshal(fus)
	if err != nil {
		return err
	}
	_, err = w.Write(j)
	return err

}
```