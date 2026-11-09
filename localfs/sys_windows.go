//go:build windows

package localfs

import (
	"os"
	"strings"
	"syscall"
	"time"

	"golang.org/x/sys/windows"
)

// reservedNames are device names Windows opens instead of a file of that
// name, with or without an extension.
var reservedNames = map[string]bool{
	"CON": true, "PRN": true, "AUX": true, "NUL": true, "CONIN$": true, "CONOUT$": true,
	"COM1": true, "COM2": true, "COM3": true, "COM4": true, "COM5": true, "COM6": true, "COM7": true, "COM8": true, "COM9": true,
	"LPT1": true, "LPT2": true, "LPT3": true, "LPT4": true, "LPT5": true, "LPT6": true, "LPT7": true, "LPT8": true, "LPT9": true,
}

// checkComponent refuses a name Windows would store as something else: one
// holding a character a Windows name cannot (a colon would open a stream of
// another file), one ending in a dot or space (both are dropped), or a
// device name.
func checkComponent(name string) error {
	for _, r := range name {
		if r < 0x20 || strings.ContainsRune(`\/:*?"<>|`, r) {
			return ErrBadName
		}
	}
	if strings.HasSuffix(name, ".") || strings.HasSuffix(name, " ") {
		return ErrBadName
	}
	stem := name
	if i := strings.IndexByte(stem, '.'); i >= 0 {
		stem = stem[:i]
	}
	if reservedNames[strings.ToUpper(strings.TrimRight(stem, " "))] {
		return ErrBadName
	}
	return nil
}

// fileID has no cheap answer from an os.FileInfo here. Zero makes the server
// hash the path instead.
func fileID(fi os.FileInfo) uint64 { return 0 }

func birthTime(fi os.FileInfo) time.Time {
	if d, ok := fi.Sys().(*syscall.Win32FileAttributeData); ok && d != nil {
		if t := time.Unix(0, d.CreationTime.Nanoseconds()); t.Unix() > 0 {
			return t
		}
	}
	return time.Time{}
}

func diskUsage(dir string) (total, free uint64, err error) {
	p, err := windows.UTF16PtrFromString(dir)
	if err != nil {
		return 0, 0, err
	}
	var freeAvail, totalBytes, totalFree uint64
	if err := windows.GetDiskFreeSpaceEx(p, &freeAvail, &totalBytes, &totalFree); err != nil {
		return 0, 0, err
	}
	return totalBytes, freeAvail, nil
}
