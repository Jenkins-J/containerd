package imageverifier

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"math"
	"net"
	"os"
	"strings"
	"testing"

	"github.com/containerd/ttrpc"
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

// test logger

type testLogger struct{}

func (tl testLogger) Debug(args ...interface{}) {
	fmt.Print("DEBUG: ", fmt.Sprint(args...))
}

func (tl testLogger) Debugf(format string, args ...interface{}) {
	format = fmt.Sprintf("%s %s", "DEBUG:", format)
	fmt.Printf(format, args...)
}

func (tl testLogger) Debugln(args ...interface{}) {
	fmt.Println("DEBUG:", fmt.Sprint(args...))
}

func (tl testLogger) Info(args ...interface{}) {
	fmt.Print("INFO: ", fmt.Sprint(args...))
}

func (tl testLogger) Infof(format string, args ...interface{}) {
	format = fmt.Sprintf("%s %s", "INFO:", format)
	fmt.Printf(format, args...)
}

func (tl testLogger) Infoln(args ...interface{}) {
	fmt.Println("INFO:", fmt.Sprint(args...))
}

func (tl testLogger) Warn(args ...interface{}) {
	fmt.Print("WARN: ", fmt.Sprint(args...))
}

func (tl testLogger) Warnf(format string, args ...interface{}) {
	format = fmt.Sprintf("%s %s", "WARN:", format)
	fmt.Printf(format, args...)
}

func (tl testLogger) Warnln(args ...interface{}) {
	fmt.Println("WARN:", fmt.Sprint(args...))
}

func (tl testLogger) Error(args ...interface{}) {
	fmt.Print("ERROR: ", fmt.Sprint(args...))
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

var _ = truststore.X509TrustStore(trustStore{})

func (t trustStore) GetCertificates(ctx context.Context, storeType truststore.Type, namedStore string) ([]*x509.Certificate, error) {
	certs := make([]*x509.Certificate, 0)

	// TODO: retrieve certs from disk/storage
	cert, err := notationX509.ReadCertificateFile("/home/ubuntu/cert")
	if err != nil {
		return certs, err
	}
	if cert != nil {
		certs = append(certs, cert...)
	}
	return certs, nil
}

// TODO: load policy from file
func loadTrustPolicy() (*trustpolicy.Document, error) {
	defaultPolicy := `
{
	"version": "1.0",
	"trustPolicies": [
			{
					"name": "default",
					"registryScopes": [
							"*"
					],
					"signatureVerification": {
							"level": "strict"
					},
					"trustStores": [
							"ca:wabbit-networks.io"
					],
					"trustedIdentities": [
							"*"
					]
			}
	]
}
`

	policy := &trustpolicy.Document{}
	err := json.Unmarshal([]byte(defaultPolicy), policy)
	if err != nil {
		return policy, fmt.Errorf("Could not decode trust policy: %s\n", err.Error())
	}
	return policy, nil
}

func (v notaryVerifier) VerifyImage(cxt context.Context, req *VerifyImageRequest) (*VerifyImageResponse, error) {
	// ORAS parse reference -> ref
	reference := fmt.Sprintf("%s@%s", req.ImageName, req.ImageDigest)
	fmt.Printf("Image to verify: %v\n", reference)

	// create repository with ref -> repo
	remoteRepo, err := remote.NewRepository(reference)
	if err != nil {
		return &VerifyImageResponse{Ok: false, Reason: err.Error()}, fmt.Errorf("Failed to create repository client: %s\n", err.Error())
	}
	remoteRepo.PlainHTTP = true
	fmt.Printf("oras remote repo: %+v\n", remoteRepo)
	repo := notationregistry.NewRepository(remoteRepo)

	store := &trustStore{}
	policy, err := loadTrustPolicy()
	if err != nil {
		return &VerifyImageResponse{Ok: false, Reason: err.Error()}, fmt.Errorf("Failed to load trust policy: %s\n", err.Error())
	}

	verifier, err := verifier.New(policy, store, nil)

	verifyOpts := notation.RemoteVerifyOptions{
		MaxSignatureAttempts: math.MaxInt64,
		ArtifactReference:    reference,
	}

	// test artifact descriptor
	artifactDes, err := repo.Resolve(cxt, verifyOpts.ArtifactReference)
	if err != nil {
		fmt.Printf("error resolving descriptor: %s\n", err.Error())
	}
	fmt.Printf("Des %+v\n", artifactDes)

	d, outcomes, err := notation.Verify(cxt, verifier, repo, verifyOpts)
	fmt.Printf("Descriptor: %+v\n", d)
	if err != nil {
		fmt.Printf("Error verifying image: %v\n", err.Error())
	}
	if outcomes == nil {
		fmt.Printf("outcomes is nil\n")
	}
	fmt.Printf("outcomes: %+v\n", outcomes)

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
	tl := testLogger{}
	ctx = log.WithLogger(ctx, tl)

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

func TestLoadTrustPolicy(t *testing.T) {
	p, err := loadTrustPolicy()
	if err != nil {
		t.Errorf("Error retrieving trust policy: %s\n", err.Error())
	}
	assert.NotEmpty(t, p)
}
