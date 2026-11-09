//go:build windows

package osfile

import (
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/sys/windows"
)

// Open is os.OpenFile that lets other handles rename and delete the file
// while it is open, as on other systems.
func Open(name string, flag int, perm os.FileMode) (*os.File, error) {
	p, err := windows.UTF16PtrFromString(longPath(name))
	if err != nil {
		return nil, &os.PathError{Op: "open", Path: name, Err: err}
	}
	var access uint32
	switch flag & (os.O_RDONLY | os.O_WRONLY | os.O_RDWR) {
	case os.O_WRONLY:
		access = windows.GENERIC_WRITE
	case os.O_RDWR:
		access = windows.GENERIC_READ | windows.GENERIC_WRITE
	default:
		access = windows.GENERIC_READ
	}
	var disposition uint32
	switch {
	case flag&(os.O_CREATE|os.O_EXCL) == os.O_CREATE|os.O_EXCL:
		disposition = windows.CREATE_NEW
	case flag&(os.O_CREATE|os.O_TRUNC) == os.O_CREATE|os.O_TRUNC:
		disposition = windows.CREATE_ALWAYS
	case flag&os.O_CREATE != 0:
		disposition = windows.OPEN_ALWAYS
	case flag&os.O_TRUNC != 0:
		disposition = windows.TRUNCATE_EXISTING
	default:
		disposition = windows.OPEN_EXISTING
	}
	attrs := uint32(windows.FILE_ATTRIBUTE_NORMAL)
	if flag&os.O_CREATE != 0 && perm&0200 == 0 {
		attrs = windows.FILE_ATTRIBUTE_READONLY
	}
	share := uint32(windows.FILE_SHARE_READ | windows.FILE_SHARE_WRITE | windows.FILE_SHARE_DELETE)
	h, err := windows.CreateFile(p, access, share, nil, disposition, attrs, 0)
	if err != nil {
		return nil, &os.PathError{Op: "open", Path: name, Err: err}
	}
	return os.NewFile(uintptr(h), name), nil
}

// longPath lets an absolute path go past MAX_PATH, as the os package does.
func longPath(p string) string {
	if len(p) < 248 || !filepath.IsAbs(p) || strings.HasPrefix(p, `\\?\`) {
		return p
	}
	if strings.HasPrefix(p, `\\`) {
		return `\\?\UNC\` + p[2:]
	}
	return `\\?\` + p
}
