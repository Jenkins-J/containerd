/*
   Copyright The containerd Authors.

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at

       http://www.apache.org/licenses/LICENSE-2.0

   Unless required by applicable law or agreed to in writing, software
   distributed under the License is distributed on an "AS IS" BASIS,
   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
   See the License for the specific language governing permissions and
   limitations under the License.
*/

package fsverity

import (
	"fmt"
	"os"
	"syscall"
	"unsafe"

	"golang.org/x/sys/unix"
)

type fsverityEnableArg struct {
	version        uint32
	hash_algorithm uint32
	block_size     uint32
	salt_size      uint32
	salt_ptr       uint64
	sig_size       uint32
	reserved1      uint32
	sig_ptr        uint64
	reserved2      [11]uint64
}

type fsverityDigest struct {
	digest_algorithm uint16
	digest_size      uint16
	digest           [64]uint8
}

const (
	maxDigestSize    int = 64
	defaultBlockSize int = 4096
)

func IsEnabled(path string) (bool, error) {
	f, err := os.Open(path)
	if err != nil {
		return false, fmt.Errorf("Error opening file: %s", err)
	}

	var attr int

	_, _, flagErr := unix.Syscall(syscall.SYS_IOCTL, f.Fd(), uintptr(unix.FS_IOC_GETFLAGS), uintptr(unsafe.Pointer(&attr)))
	if flagErr != 0 {
		return false, fmt.Errorf("Error getting inode flags: %s", flagErr)
	}

	if attr&unix.FS_VERITY_FL == unix.FS_VERITY_FL {
		return true, nil
	}

	return false, nil
}

func Enable(path string) error {
	f, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("Error opening file: %s\n", err.Error())
	}

	var args *fsverityEnableArg = &fsverityEnableArg{}
	args.version = 1
	args.hash_algorithm = 1

	blockSize := unix.Getpagesize()
	if blockSize <= 0 {
		blockSize = defaultBlockSize
	}
	args.block_size = uint32(blockSize)

	_, _, errno := unix.Syscall(syscall.SYS_IOCTL, f.Fd(), uintptr(unix.FS_IOC_ENABLE_VERITY), uintptr(unsafe.Pointer(args)))
	if errno != 0 {
		return fmt.Errorf("Enable fsverity failed: %d\n", errno)
	}

	return nil
}

func Measure(path string) (string, error) {
	var verityDigest string
	f, err := os.Open(path)
	if err != nil {
		return verityDigest, fmt.Errorf("Error opening file: %s\n", err.Error())
	}

	var d *fsverityDigest = &fsverityDigest{digest_size: maxDigestSize}
	_, _, errno := unix.Syscall(syscall.SYS_IOCTL, f.Fd(), uintptr(unix.FS_IOC_MEASURE_VERITY), uintptr(unsafe.Pointer(d)))
	if errno != 0 {
		return verityDigest, fmt.Errorf("Measure fsverity failed: %d\n", errno)
	}

	var i uint16
	for i = 0; i < (*d).digest_size; i++ {
		verityDigest = fmt.Sprintf("%s%x", verityDigest, (*d).digest[i])
	}

	return verityDigest, nil
}
