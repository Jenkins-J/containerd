package imageverifier

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io/fs"
	"math"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/containerd/ttrpc"
	_ "github.com/notaryproject/notation-core-go/signature/cose"
	_ "github.com/notaryproject/notation-core-go/signature/jws"
	notationX509 "github.com/notaryproject/notation-core-go/x509"
	"github.com/notaryproject/notation-go"
	"github.com/notaryproject/notation-go/log"
	"github.com/notaryproject/notation-go/verifier"
	"github.com/notaryproject/notation-go/verifier/trustpolicy"
	"github.com/notaryproject/notation-go/verifier/truststore"
	"github.com/stretchr/testify/assert"

	// "oras.land/oras-go/v2/registry"
	notationregistry "github.com/notaryproject/notation-go/registry"
	"oras.land/oras-go/v2/registry/remote"
)

const socket = "/tmp/imageverifier.sock"

var verifierConfiguration verifyConfig

// test logger

type testLogger struct{}

func (tl testLogger) Debug(args ...interface{}) {
	fmt.Print("DEBUG: ", fmt.Sprint(args...), "\n")
}

func (tl testLogger) Debugf(format string, args ...interface{}) {
	format = fmt.Sprintf("%s %s", "DEBUG:", format)
	fmt.Printf(format, args...)
}

func (tl testLogger) Debugln(args ...interface{}) {
	fmt.Println("DEBUG:", fmt.Sprint(args...))
}

func (tl testLogger) Info(args ...interface{}) {
	fmt.Print("INFO: ", fmt.Sprint(args...), "\n")
}

func (tl testLogger) Infof(format string, args ...interface{}) {
	format = fmt.Sprintf("%s %s", "INFO:", format)
	fmt.Printf(format, args...)
}

func (tl testLogger) Infoln(args ...interface{}) {
	fmt.Println("INFO:", fmt.Sprint(args...))
}

func (tl testLogger) Warn(args ...interface{}) {
	fmt.Print("WARN: ", fmt.Sprint(args...), "\n")
}

func (tl testLogger) Warnf(format string, args ...interface{}) {
	format = fmt.Sprintf("%s %s", "WARN:", format)
	fmt.Printf(format, args...)
}

func (tl testLogger) Warnln(args ...interface{}) {
	fmt.Println("WARN:", fmt.Sprint(args...))
}

func (tl testLogger) Error(args ...interface{}) {
	fmt.Print("ERROR: ", fmt.Sprint(args...), "\n")
}

func (tl testLogger) Errorf(format string, args ...interface{}) {
	format = fmt.Sprintf("%s %s", "ERROR:", format)
	fmt.Printf(format, args...)
}

func (tl testLogger) Errorln(args ...interface{}) {
	fmt.Println("ERROR:", fmt.Sprint(args...))
}

type notaryVerifier struct{}
type trustStore struct{}
type verifyConfig struct {
	InsecureRegistries []string             `json"insecureRegistries,omitempty"`
	CertLocations      []string             `json:"certs"`
	Policy             trustpolicy.Document `json:"policy"`
}

var _ = truststore.X509TrustStore(trustStore{})

func (t trustStore) GetCertificates(ctx context.Context, storeType truststore.Type, namedStore string) ([]*x509.Certificate, error) {
	certs := make([]*x509.Certificate, 0)

	for _, path := range verifierConfiguration.CertLocations {
		walkErr := filepath.WalkDir(path, func(path string, d fs.DirEntry, e error) error {
			if e != nil {
				fmt.Printf("Error walking directory tree: %s\n", e.Error())
			}
			fmt.Printf("%+v\n", d)
			if !(d.IsDir()) {
				cert, err := notationX509.ReadCertificateFile(path)
				if err != nil {
					// return certs, err
					fmt.Printf("Error loading cert: %s\n", err.Error())
				}
				if cert != nil {
					certs = append(certs, cert...)
				}
			}
			return nil
		})
		if walkErr != nil {
			fmt.Printf("Walk Error, ending walk: %s\n", walkErr.Error())
			break
		}
	}
	return certs, nil
}

func getDefaultConfigPath() string {
	var configPath string
	homeDir := os.Getenv("HOME")
	configPath = filepath.Join(homeDir, ".containerv", "config.json")
	return configPath
}

func loadConfig() (verifyConfig, error) {
	configPath := getDefaultConfigPath()
	config := verifyConfig{}

	content, err := os.ReadFile(configPath)
	if err != nil {
		return config, fmt.Errorf("Error reading config file: %s\n", err.Error())
	}
	err = json.Unmarshal(content, &config)
	if err != nil {
		return config, fmt.Errorf("Error reading config file: %s\n", err.Error())
	}

	return config, nil

}

func (v notaryVerifier) VerifyImage(ctx context.Context, req *VerifyImageRequest) (*VerifyImageResponse, error) {
	// ORAS parse reference -> ref
	reference := fmt.Sprintf("%s@%s", req.ImageName, req.ImageDigest)

	// create repository with ref -> repo
	remoteRepo, err := remote.NewRepository(reference)
	if err != nil {
		return &VerifyImageResponse{Ok: false, Reason: err.Error()}, fmt.Errorf("Failed to create repository client: %s\n", err.Error())
	}
	// TODO: choose if repository is http or https
	remoteRepo.PlainHTTP = true
	repo := notationregistry.NewRepository(remoteRepo)

	store := &trustStore{}
	policy := &verifierConfiguration.Policy
	if err != nil {
		return &VerifyImageResponse{Ok: false, Reason: err.Error()}, fmt.Errorf("Failed to load trust policy: %s\n", err.Error())
	}

	verifier, err := verifier.New(policy, store, nil)

	verifyOpts := notation.RemoteVerifyOptions{
		MaxSignatureAttempts: math.MaxInt64,
		ArtifactReference:    reference,
	}

	// set logger to get notary logs
	tl := testLogger{}
	ctx = log.WithLogger(ctx, tl)

	_, outcomes, err := notation.Verify(ctx, verifier, repo, verifyOpts)
	if err != nil {
		return &VerifyImageResponse{Ok: false, Reason: fmt.Sprintf("Error verifying image: %v\n", err.Error())}, nil
	}

	var ok bool = true
	reasons := make([]string, 0)
	for _, outcome := range outcomes {
		if outcome.Error != nil {
			ok = false
			reasons = append(reasons, outcome.Error.Error())
		}
	}

	if !ok {
		r := strings.Join(reasons, "; ")
		return &VerifyImageResponse{Ok: ok, Reason: r}, nil
	}

	return &VerifyImageResponse{Ok: ok, Reason: "Passed all verifications"}, nil
}

func TestMain(m *testing.M) {
	c, err := loadConfig()
	if err != nil {
		fmt.Printf("Error loading configuration file: %s\n", err.Error())
	}
	verifierConfiguration = c

	server, err := ttrpc.NewServer()
	if err != nil {
		fmt.Printf("Error creating ttrpc server: %s\n", err.Error())
	}

	RegisterImageVerifierService(server, &notaryVerifier{})

	l, err := net.Listen("unix", socket)
	if err != nil {
		fmt.Printf("Error listening on socket: %s\n", err.Error())
	}
	defer func() {
		server.Close()
		os.Remove(socket)
	}()

	go func() {
		err = server.Serve(context.Background(), l)
		if err != nil {
			fmt.Printf("Server returned an error: %s\n", err.Error())
		}
	}()

	m.Run()

}

func TestVerifyImage(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping TestVerifyImage: testing in short mode")
	}
	conn, err := net.Dial("unix", socket)
	if err != nil {
		t.Errorf("Error: %s\n", err.Error())
	}
	defer conn.Close()

	tc := ttrpc.NewClient(conn)
	client := NewImageVerifierClient(tc)

	r := &VerifyImageRequest{
		ImageName:   "image name here",
		ImageDigest: "image digest here",
	}

	ctx := context.Background()

	resp, err := client.VerifyImage(ctx, r)
	if err != nil {
		t.Errorf("Error: %s\n", err.Error())
	}

	fmt.Printf("Response Ok: %v\n", resp.Ok)
	fmt.Printf("Response Reason: %v\n", resp.Reason)

}

func TestGetCertificate(t *testing.T) {
	ts := &trustStore{}
	ctx := context.Background()

	c, err := ts.GetCertificates(ctx, truststore.TypeCA, "")
	if err != nil {
		t.Errorf("Error retrieving certificates: %s\n", err.Error())
	}
	assert.NotEmpty(t, c)
}

func TestLoadConfig(t *testing.T) {
	config, err := loadConfig()
	if err != nil {
		fmt.Printf("Error loading config: %s\n", err.Error())
	}

	assert.Nil(t, err)
	assert.NotNil(t, config)
	assert.NotEmpty(t, config)
}
