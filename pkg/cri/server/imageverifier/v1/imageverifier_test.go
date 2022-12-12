package imageverifier

import (
	"context"
	"fmt"
	"net"
	"os"
	"testing"

	"github.com/containerd/ttrpc"
)

const socket = "/run/imageverifier/v1.sock"

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
	defer server.Close()

	RegisterImageVerifierService(server, &notaryVerifier{})

	l, err := net.Listen("unix", socket)
	if err != nil {
		fmt.Printf("Error listening on socket: %s\n", err.Error())
	}
	defer func() {
		l.Close()
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
