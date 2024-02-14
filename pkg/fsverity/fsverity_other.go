//go:build !linux

package fsverity

func IsSupported(_ string) (bool, error) {
	return false, nil
}
