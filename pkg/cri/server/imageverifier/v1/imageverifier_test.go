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
	"github.com/notaryproject/notation-go/verifier"
	"github.com/notaryproject/notation-go/verifier/trustpolicy"
	"github.com/notaryproject/notation-go/verifier/truststore"

	// "oras.land/oras-go/v2/registry"
	notationregistry "github.com/notaryproject/notation-go/registry"
	"oras.land/oras-go/v2/registry/remote"
)

const socket = "/tmp/imageverifier.sock"

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
		certs = append(certs, cert)
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
							"ca:certs"
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
	// ref, err := registry.ParseReference(reference)

	// create repository with ref -> repo
	remoteRepo := remote.NewRepository(reference)
	repo := notationregistry.NewRepository(remoteRepo)

	store := &trustStore{}
	policy, err := loadTrustPolicy()
	if err != nil {
		return &VerifyImageResponse{Ok: false, Reason: err.Error()}, fmt.Errorf("Failed to load trust policy: %s\n", err.Error())
	}

	verifier, err := verifier.New(policy, store, nil)

	verifyOpts := notation.RemoteVerifyOptions{
		MaxSignatureAttempts: math.MaxInt64,
	}
	_, outcomes, err := notation.Verify(cxt, verifier, repo, verifyOpts)

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
	fmt.Printf("Hello from TestMain\n")

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
	fmt.Printf("Testing GetCertificate\n")
}

func TestLoadTrustPolicy(t *testing.T) {
	fmt.Printf("Testing TestLoadTrustPolicy\n")
}
