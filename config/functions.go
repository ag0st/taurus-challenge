/*
Package config allows to use a file as configuration for the service.

It uses gopkg.in/yaml.v3 package in order to parse the configuration file. It contains the whole structure of the
configuration with root element being the structure Config.

It offers the capacity to retrieve the configuration file path from different endpoints:
- CLI flag (-config [path]) default = config.yaml
- Environment variable (CONFIG_FILE=[path])

Particularities:
 1. If both endpoints are detected, it will use environment variable.
 2. If no endpoints explicitly given (no detection of env var & no flag given in argument) it will use the default path
    "./config.yaml"

Below, an example of how to use the package:

	cfgPath, err := config.ParseFlags()
	if err != nil {
		logging.Fatal(err)
	}
	cfg, err := config.NewConfig(cfgPath)
	if err != nil {
		logging.Fatal(err)
	}

Author: Romain Agostinelli
Email: romain.agostinelli1@swisscom.com
*/
package config

import (
	"encoding/hex"
	"flag"
	"fmt"
	"os"
	"path/filepath"

	"github.com/ag0st/taurus-challenge/errs"
	"gopkg.in/yaml.v3"
)

var currentConfig *Config

// Declaration of the configuration type used inside the program.
// Using getter instead of public members to prevent the modification
// of the configuration.

type Config struct {
	service Service
	minio   MinIo
}

func (c *Config) Service() *Service { return &c.service }
func (c *Config) Minio() *MinIo     { return &c.minio }

type Service struct {
	address   string
	chunkSize uint64
	aesKey    [32]byte
}

func (s *Service) Address() string   { return s.address }
func (s *Service) ChunkSize() uint64 { return s.chunkSize }
func (s *Service) AESKey() [32]byte  { return s.aesKey }

type MinIo struct {
	accessKey string
	secretKey string
	endpoint  string
	bucket    string
}

func (m *MinIo) AccessKey() string { return m.accessKey }
func (m *MinIo) SecretKey() string { return m.secretKey }
func (m *MinIo) Endpoint() string  { return m.endpoint }
func (m *MinIo) Bucket() string    { return m.bucket }

// ValidateConfigPath just makes sure, that the path provided is a file,
// that can be read
func ValidateConfigPath(path string) error {
	abs, err2 := filepath.Abs(path)
	if err2 != nil {
		return err2
	}
	s, err := os.Stat(abs)
	if err != nil {
		return err
	}
	if s.IsDir() {
		return errs.New(fmt.Sprintf("'%s' is a directory, not a normal file", path))
	}
	return nil
}

// ParseFlags will create and parse the CLI flags
// and return the path to be used elsewhere
func ParseFlags() (string, error) {
	// String that contains the configured configuration path
	var configPath string

	// Set up a CLI flag called "-config" to allow users
	// to supply the configuration file
	flag.StringVar(&configPath, "config", "config.yaml", "path to config file")

	// Actually parse the flags
	flag.Parse()

	getenv := os.Getenv("CONFIG_FILE")
	if len(getenv) > 0 {
		// use environment variable instead
		configPath = getenv
	}

	// Validate the path first
	if err := ValidateConfigPath(configPath); err != nil {
		return "", err
	}

	// Return the configuration path
	return configPath, nil
}

// NewConfig returns a new decoded Config struct
func NewConfig(configPath string) (*Config, error) {
	// Create config structure
	configyml := &ConfigYml{}

	// Open config file
	file, err := os.Open(configPath)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	// Init new YAML decode
	d := yaml.NewDecoder(file)

	// Start YAML decoding from file
	if err := d.Decode(&configyml); err != nil {
		return nil, err
	}

	// convert to program config
	chunkSize, err := extractSize(configyml.Service.ChunkSizeStr)
	if err != nil {
		return nil, err
	} else if chunkSize != 0 && (chunkSize < 5<<20 || chunkSize > 5<<30) {
		return nil, errs.New("chunk size must be between 5<<20 and 5<<30 (included)")
	}

	skey, err := hex.DecodeString(configyml.Service.AESEncryptionKey)
	if err != nil {
		return nil, err
	}
	key := [32]byte{}
	n := copy(key[:], skey)
	if n != 32 {
		return nil, errs.New("cannot convert the aes key into byte array")
	}
	cfg := Config{
		service: Service{address: configyml.Service.Address, chunkSize: chunkSize, aesKey: key},
		minio: MinIo{
			accessKey: configyml.MinIo.AccessKey,
			secretKey: configyml.MinIo.SecretKey,
			endpoint:  configyml.MinIo.Endpoint,
			bucket:    configyml.MinIo.Bucket,
		},
	}

	currentConfig = &cfg

	return currentConfig, nil
}

// GetCurrent gives the current config. This method panic if NewConfig has not been called before without error
func GetCurrent() *Config {
	if currentConfig == nil {
		panic(errs.New("config not loaded"))
	}
	return currentConfig
}
