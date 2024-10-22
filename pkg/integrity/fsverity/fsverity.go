package fsverity

import (
	"fmt"
	"io"
	"os"
	"path/filepath"

	fsv "github.com/containerd/containerd/v2/internal/fsverity"
	"github.com/containerd/containerd/v2/pkg/integrity"
	"github.com/containerd/errdefs"
)

// TODO: add integrity plugin as content store plugin dependency
// TODO: decide on appropriate place for configuration options

type validator struct {
	integrityStorePath string
}

type Config struct {
	StorePath string `toml:"store_path"`
	// key pair for signatures?
}

var _ integrity.Verifier = validator{}

func NewValidator(config Config) validator {
	return validator{integrityStorePath: config.StorePath}
}

// Enable validation on the blob by taking an initial measurement
// and storing it for later comparison.
func (v validator) Register(blob string) (string, error) {
	var verityDigest string
	// Enable fsverity digest verification on the blob
	if err := fsv.Enable(blob); err != nil {
		return verityDigest, fmt.Errorf("failed to enable fsverity verification: %s", err.Error())
	}

	verityDigest, merr := fsv.Measure(blob)
	if merr != nil {
		return verityDigest, fmt.Errorf("failed to take fsverity measurement of blob: %s", merr.Error())
	}

	// TODO: sign the digest with a key? (get key from configuration options?)

	digest := filepath.Base(blob)

	if err := os.MkdirAll(v.integrityStorePath, 0755); err != nil {
		return verityDigest, fmt.Errorf("Failed to create integrity store: %w", err)
	}

	integrityFilePath := filepath.Join(v.integrityStorePath, digest)
	integrityFile, err := os.Create(integrityFilePath)
	if err != nil {
		return verityDigest, fmt.Errorf("Failed to register blob integrity: %w", err)
	}
	defer integrityFile.Close()

	_, err = integrityFile.Write([]byte(verityDigest))
	if err != nil {
		return verityDigest, fmt.Errorf("Failed to register blob integrity: %w", err)
	}

	return verityDigest, nil
}

// Validate the blob by measuring the content and comparing it to
// the stored digest.
func (v validator) IsValid(blob string) (bool, error) {
	measure := func() (string, error) {
		var verityDigest string
		// check that fsverity is enabled on the blob before reading
		// if not, it may not be trustworthy
		enabled, err := fsv.IsEnabled(blob)
		if err != nil {
			return verityDigest, fmt.Errorf("Error checking fsverity status of blob %s: %s", blob, err.Error())
		}
		if !enabled {
			return verityDigest, fmt.Errorf("fsverity not enabled on blob %s", blob)
		}

		verityDigest, merr := fsv.Measure(blob)
		if merr != nil {
			return verityDigest, fmt.Errorf("failed to take fsverity measurement of blob: %s", merr.Error())
		}
		return verityDigest, nil
	}

	verityDigest, err := measure()
	if err != nil {
		return false, fmt.Errorf("failed to measure blob: %w", err)
	}

	var expectedDigest string
	digest := filepath.Base(blob)
	integrityFile := filepath.Join(v.integrityStorePath, digest)
	ifd, err := os.Open(integrityFile) // TODO: validate the signed digest next?
	if err != nil {
		return false, fmt.Errorf("could not read expected integrity value of %s", blob)
	}
	b, err := io.ReadAll(ifd)
	if err == nil {
		expectedDigest = string(b)
	}

	// compare the digest to the known "good" value
	if verityDigest != expectedDigest {
		return false, fmt.Errorf("blob not trusted: fsverity digest does not match the expected digest value")
	}

	return true, nil
}

// Remove the stored digest when no longer needed
func (v validator) Unregister(blob string) error {
	digest := filepath.Base(blob)
	integrityFile := filepath.Join(v.integrityStorePath, digest)

	if err := os.RemoveAll(integrityFile); err != nil {
		if !os.IsNotExist(err) {
			return err
		}

		return fmt.Errorf("integrity file %v: %w", digest, errdefs.ErrNotFound)
	}
	return nil
}
