package imageverifier

import (
	"context"
	"fmt"
	"net"
	"os"
	"testing"

	"github.com/containerd/ttrpc"
)

const socket = "/tmp/imageverifier.sock"

type notaryVerifier struct{}

func (v notaryVerifier) VerifyImage(cxt context.Context, req *VerifyImageRequest) (*VerifyImageResponse, error) {
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

func TestHello(t *testing.T) {
	fmt.Printf("Hello there!")
}

func TestVerifyImage(t *testing.T) {
	conn, err := net.Dial("unix", socket)
	if err != nil {
		t.Errorf("Error: %s\n", err.Error())
	}
	defer conn.Close()

	tc := NewClient(conn)
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
