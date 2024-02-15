//go:build !linux

package fsverity

func IsSupported() bool {
	return false
}
