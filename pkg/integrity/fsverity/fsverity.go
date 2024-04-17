package fsverity

import (
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/containerd/containerd/v2/errdefs"
	fsv "github.com/containerd/containerd/v2/pkg/fsverity"
	"github.com/containerd/containerd/v2/pkg/integrity"
)

// TODO: add integrity plugin as content store plugin dependency
// TODO: decide on appropriate place for configuration options

type validator struct {
	integrityStorePath string
}

type Config struct {
	StorePath string
	// key pair for signatures?
}

var _ integrity.Validator = validator{}

func NewValidator(config Config) validator {
	return validator{integrityStorePath: config.StorePath}
}

// Enable validation on the blob by taking an initial measurement
// and storing it for later comparison.
func (v validator) Register(blob string) (string, error) {
	var verityDigest string
	// Enable fsverity digest verification on the blob
	if err := fsverity.Enable(blob); err != nil {
		return verityDigest, fmt.Errorf("failed to enable fsverity verification: %s", err.Error())
	}

	verityDigest, merr := fsverity.Measure(blob)
	if merr != nil {
		return verityDigest, fmt.Errorf("failed to take fsverity measurement of blob: %s", merr.Error())
	}

	// TODO: sign the digest with a key? (get key from configuration options?)

	digest := filepath.Base(blob)

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
		enabled, err := fsv.IsEnabled(p)
		if err != nil {
			return verityDigest, fmt.Errorf("Error checking fsverity status of blob %s: %s", p, err.Error())
		}
		if !enabled {
			return verityDigest, fmt.Errorf("fsverity not enabled on blob %s", p)
		}

		verityDigest, merr := fsv.Measure(p)
		if merr != nil {
			return verityDigest, fmt.Errorf("failed to take fsverity measurement of blob: %s", merr.Error())
		}
		return verityDigest, nil
	}

	verityDigest, err := measure()
	if err == nil {
		var expectedDigest string
		digest := filepath.Base(blob)
		integrityFile := filepath.Join(v.integrityStorePath, digest)
		ifd, err := os.Open(integrityFile) // TODO: validate the signed digest next?
		if err != nil {
			return nil, fmt.Errorf("could not read expected integrity value of %s", p)
		}
		b, err := io.ReadAll(ifd)
		if err == nil {
			expectedDigest = string(b)
		}

		// compare the digest to the "good" value stored in the blob label
		if verityDigest != expectedDigest {
			return nil, fmt.Errorf("blob not trusted: fsverity digest does not match the expected digest value")
		}
	}
	return nil
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
