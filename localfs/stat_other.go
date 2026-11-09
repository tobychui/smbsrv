//go:build !unix && !windows

package localfs

import (
	"errors"
	"os"
	"time"
)

func fileID(fi os.FileInfo) uint64 { return 0 }

func birthTime(fi os.FileInfo) time.Time { return time.Time{} }

func diskUsage(dir string) (total, free uint64, err error) {
	return 0, 0, errors.New("localfs: disk usage is not known on this system")
}
