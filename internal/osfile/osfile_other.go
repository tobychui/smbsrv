//go:build !windows

package osfile

import "os"

// Open is os.OpenFile: open files can be renamed and removed here already.
func Open(name string, flag int, perm os.FileMode) (*os.File, error) {
	return os.OpenFile(name, flag, perm)
}
