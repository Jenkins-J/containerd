//go:build !linux

package fsverity

func IsSupported(rootPath string) bool {
	return false
}
