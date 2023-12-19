# Description

The goal of this service is to encrypt files before pushing them to a MinIo bucket.

You can add a new file, retrieve the list of files, and download a specific file.

## Launch

First, launch a MinIo server using the [docker-compose.yaml](./docker-compose.yaml) file.

Then create a configuration (you can use the one given as example [config.yaml](./config.yaml)).


Build the exec file
```sh
go build
```

Launch the service with `-config` argument.
```sh
./taurus-challenge -config config.yaml
```

## Usage

You can use the service with `Curl` as shown below:

#### Upload a file:
Upload file using original filename
```sh
curl -F 'file=@/path/to/file' http://127.0.0.1:8080/api/file | jq
```
Upload file using another object name
```sh
curl -F 'file=@/path/to/file' -F 'object_name=other_object_name' http://127.0.0.1:8080/api/file | jq
```

#### List all files:
```sh
curl http://127.0.0.1:8080/api/file | jq
```

#### Download a file
```sh
curl -O http://127.0.0.1:8080/api/file/object_name
```



## Configuration
This implementation works with a configuration file in YAML format. 

The configuration file can be passed with the argument `-config`.

Here an example : 
```yaml
service:
  address: ':8080'
  # format: xx yy where 
  #   xx = 0 or (5 MiB <= xx <= 5 GiB) 
  #   yy = B or KiB or MiB or GiB
  chunk_size: 0 MiB
  # hex format 256 aes key
  aes_encryption_key: 000102030405060708090A0B0C0D0E0FF0E0D0C0B0A090807060504030201000

minio:
  access_key: 'JgfDSlT6yRBmM8tX4GRr'
  secret_key: 'Q0zNgsGFTVeiU8gpTLSG3kVgAvNZeuVZ4E2WZsZ6'
  endpoint: '127.0.0.1:9000'
  bucket: 'testbucket'
```

Under the `service` key, there is all the option for the service, like api address, chunk size and encryption key.

Under the `minio` key, there is all the MinIo specific configuration.

| *Config name*              | *Type* | *Description and constraints*                                                                                                                                                                             |
|----------------------------|--------|-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| service.address            | string | The address on which the service will be available                                                                                                                                                        |
| service.chunk_size         | string | The chunk size it uses for encryption AND upload.  If chunk size == "0 B", it use the whole file type encryption AND whole file type upload. Constraints: must finish with "B" or "KiB" or "MiB" or "GiB" and must be 0 or 5 MiB <= x <= 5 GiB |
| service.aes_encryption_key | string | Hex format AES 256 key                                                                                                                                                                                    |
| minio.access_key           | string | MinIo access key                                                                                                                                                                                          |
| minio.secret_key           | string | MinIo secret key                                                                                                                                                                                          |
| minio.endpoint             | string | The endpoint where the MinIo service is available                                                                                                                                                         |
| minio.bucket               | string | The MinIo bucket to use                                                                                                                                                                                   |

# Documentation
This section contains the documentation of the project. It explains the global working principle and the principal architectural choices made. More documentation is available in the code itself.

## Working principle
The service is able to push, list and download objects from a MinIo database. 
The objects are stored encrypted. The role of the service is to encrypt objects before pushing them on MinIo and decrypt them before returning to the user on a download.
The implementation supports two ways of encrypting files and two ways to push files.

For both (encryption and push) the two ways are :
- the whole file
- by chunk

The whole file encryption/upload get the file completely in memory and then, encrypt/upload it in one chunk of the size of the file.
The chunk encryption/upload process a file in stream of multiple small chunks. In the case of encryption, all the chunks are encrypted individually. For the upload, the chunk version use the implementation of multipart upload. Each parts are uploaded one after the other to MinIo

This implementation of upload and encryption use the interfaces io.Writer to integrate easily with other implementations (std lib, other libraries).

On the other hand, the decryption process is implemented as a io.Reader for the same reason.

It allows to chain the writers as so:
`encrptionWriter(storeWriter)`

## Encryption / Decryption

The encryption and decryption are based on the AES GCM algorithm that allows not only to encrypt/decrypt, but also to authenticate the data. This way, the encrypted data at rest cannot be altered.

AES GCM is able to authenticate non-encrypted data, which is useful to store other data linked to the file (as filename and size) that do not need to be encrypted.

### Format

To facilitate decryption and store necessary information for decryption, the encrypted data comes with an header.

This header contains the filename (limited to 50 bytes), the chunkSize (if 0 = whole file encryption) and the IV.

Only the filename and the chunkSize are authenticated via AAD. The IV does not need to be authenticated as it is already done in the algorithm.

The IV is also not secret.

This is the structure of the header:
| 50 B     | 8B         | 12B |
|----------|------------|-----|
| Filename | Chunk Size | IV  |

The header is a total of 70 bytes. Regardless of the type of encryption (whole file or by chunk), the same header is always the same and present once at the beggining of the data.

The parameters choosed for the encryption are 12B IV and 16B tag, which are the default in Go std library.

### Whole file

The whole file encryption is implemented as a io.WriterCloser that read the plaintext data into an internal buffer and on the Close, it seals the data and push it to the underlying io.Writer.

###  Chunk

The chunk encryption method is implemented as a io.WriterCloser that reads the data, if there is enough for a chunk seals it and push it to the underlying io.Writer.

The difference when doing chunk encryption, is that we need to store the sequence of the chunks. For this, in front of each encrypted chunk, the sequence number is added. The sequence number is encoded on a 32-bits unsigned integer, therefore, the maximum chunk sequence number is `0xFFFF_FFFF`.
To encrypt each chunk, it XOR the last four bytes of the IV (present in the header) with the chunk sequence number. This way, the chunk sequence number is automatically authenticated (fixed BigEndian).

The decryption has to do the same, first getting the chunk sequence number, then XORing it with the IV and decrypt the chunk. The decryption also check that the chunk comes in sequence.

By doing so, it prevents to be able to change the chunk order, as each chunk is encrypted with a different IV. It is not possible to exchange a chunk with a chunk from another file (same sequence number) as the IV is unique for each file.

One of the advantage of this technique for future improvements, is that it can be easily parallelizable.

## Storage

The store package uses the MinIo Golang SDK to communicate with the MinIo instance. There is two style of upload implemented:
- whole file : it uploads an object in one request (forced in this application to make the difference between chunks)
- chunk : it uploads the data by chunk using the MinIo implementation of MutliPart upload.

The service creates the bucket if it does not already exist.

### Whole file
In this implementation, the file is forced to be uploaded in one request. We could let the MinIo SDK to choose if it must be splitted or not, but for the puropose of this exercice, I choosed to fix to one request to differentiate with chunk type. 

If this application is used, it would be better to let the SDK choose for us.

The implementation of a whole file uplaod is done via a io.WriterCloser that store the data it has to write inside an internal buffer and only on the call of Close function, uploads it to the MinIo bucket.

### Chunk

The chunk method consist of a io.WriterCloser that for each call to Write, send the data to MinIo. It is the responsability of the caller to ensure that the data are the right size.

It uses the implementation of the MultiPart upload of MinIo. At the first write, it creates a new MultiPart upload and on the subsequent write, writes a new part.
Finally, on Close, it completes the the MultiPart upload.

MinIo has some constraint on the usage of MultiPart upload:
- Each part must be between 5MiB and 5GiB (only exception for the last one).
- The maximum number of parts is 10'000.

It is to the user to configure the right size of chunks in the configuration to support its use case.

These values are hardcoded in MinIo and this service will check on this values and throw an error if the file is not supported.
Description here :[limits and thresholds](https://min.io/docs/minio/linux/operations/concepts/thresholds.html)
- Min of 5MiB for chunk is here : [code line for 5MiB](https://github.com/minio/minio/blob/b3314e97a64a42d22ba5b939917939d72a28c97d/cmd/utils.go#L273C12-L273C12)
- Max of 10'000 chunk is here : [code line for 10'000 max sequence number](https://github.com/minio/minio/blob/b3314e97a64a42d22ba5b939917939d72a28c97d/cmd/utils.go#L277)

## API

This API is implemented without using an external library. It has two paths:
- `/api/file` : GET (gets the list of files) and POST (add a new file of upload new version)
- `/api/file/{object_name}` : GET (return a file)

The API and its answers are described in an OpenApi 3.0 format in this [file](./api.yaml)

Regarding file upload, the current implementation use `ContentType multipart/form-data` and use the built in `ParseMultipartForm` with an hardcoded 100 MiB in memory maxium. It download all the data from the request and if it is bigger than 100 MiB, it stores it into a temporary file.
This is not optimum as we have to store the file in the memory or on the disk instead of working in stream.


The request handling follow a _middleware pattern_ where the request go through multiple handlers. In this implementation, there is two handler : the `errorHandler` and the `httpHandler` The `httpHandle` is the "final" handler with parse the request. Both can be chained as `errorHandler(httpHandler())`. The goal of the `errorHandler` is convert the errors returned from the service to the user. By using this pattern, we can then add multiple layers of handling, like a security handler (token verification), a logging handler, a metric handler, etc.

# Improvements
There are several improvement that can be added to this implementation.

First, more unit testing. Mocks for MinIo tests are already implemented but are not fully used (time constraint).

Second, the upload of the file from the client must be improved to be able to parse the file in a stream to avoid big usage of memory / disk.

Third, more endpoint can be added (deleting a file for example).

Fourth, the logging can be improved by adding another handler or accross the implementation.