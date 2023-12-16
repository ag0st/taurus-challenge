package config

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/ag0st/taurus-challenge/errs"
)

// Config is the object used for the configuration in the application. It is used as
// unmarshall object for the config.yaml file
type ConfigYml struct {
	Service ServiceYml `yaml:"service"`
	MinIo   MinIoYml   `yaml:"minio"`
}

type ServiceYml struct {
	Address          string `yaml:"address"`
	ChunkSizeStr     string `yaml:"chunk_size"`
	AESEncryptionKey string `yaml:"aes_encryption_key"`
}

type MinIoYml struct {
	AccessKey string `yaml:"access_key"`
	SecretKey string `yaml:"secret_key"`
	Endpoint  string `yaml:"endpoint"`
	Bucket    string `yaml:"bucket"`
}

// extractSize take a string formatted size which can be given in the configuration file
// and format it as int (representing the number of bytes).
// The size parameter is size formatted in string (with MB, GB, KB suffix) and what is
// used in log to tell which field failed.
func extractSize(size string) (uint64, error) {
	split := strings.Split(size, " ") // space separator
	if len(split) != 2 {
		return 0, errs.New(fmt.Sprintf("cannot parse %s, must be of type: \n "+
			"xx yy : where xx is an int and yy is one of [B, KBi, MBi, GBi]", size))
	}
	var shifter = 0
	switch split[1] {
	case "B": // byte
		break
	case "KBi": // kilobytes
		shifter = 10
	case "MBi": // megabytes
		shifter = 20
	case "GBi": // gigabytes
		shifter = 30
	default:
		return 0, errs.New(fmt.Sprintf("unit uknown [%s], use [B, KBi, MBi, GBi]", split[1]))
	}
	quantity, err := strconv.Atoi(split[0])
	if err != nil {
		return 0, err
	}
	return uint64(quantity) << shifter, nil
}
