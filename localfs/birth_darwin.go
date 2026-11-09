//go:build darwin

package localfs

import (
	"os"
	"syscall"
	"time"
)

// birthTime is the creation time APFS and HFS+ keep in stat.
func birthTime(fi os.FileInfo) time.Time {
	if st, ok := fi.Sys().(*syscall.Stat_t); ok && st != nil && st.Birthtimespec.Sec > 0 {
		return time.Unix(st.Birthtimespec.Sec, st.Birthtimespec.Nsec)
	}
	return time.Time{}
}
