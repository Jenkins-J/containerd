package imageverifier

import (
	"context"
	"fmt"
	"math"
	"net"
	"os"
	"testing"

	"github.com/containerd/ttrpc"
	"github.com/notaryproject/notation-go"
	"github.com/notaryproject/notation-go/verifier"

	// "oras.land/oras-go/v2/registry"
	notationregistry "github.com/notaryproject/notation-go/registry"
	"oras.land/oras-go/v2/registry/remote"
)

const socket = "/tmp/imageverifier.sock"

type notaryVerifier struct{}

func (v notaryVerifier) VerifyImage(cxt context.Context, req *VerifyImageRequest) (*VerifyImageResponse, error) {
	// ORAS parse reference -> ref
	reference := fmt.Sprintf("%s@%s", req.ImageName, req.ImageDigest)
	// ref, err := registry.ParseReference(reference)

	// create repository with ref -> repo
	remoteRepo := remote.NewRepository(reference)
	repo := notationregistry.NewRepository(remoteRepo)

	// use repo to run notation Verify func

	// TODO: get trust policy and trust store to create verifier
	// 1. create struct to implement store interface (notation X509TrustStore)
	// 2. create/read trust policy document (notation trustpolicy Document)
	verifier, err := verifier.New(policy, store, nil)
	verifyOpts := notation.RemoteVerifyOptions{
		MaxSignatureAttempts: math.MaxInt64,
	}
	_, outcomes, err := notation.Verify(cxt, verifier, repo, verifyOpts)
	return &VerifyImageResponse{Ok: false, Reason: "This will always fail"}, nil
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
