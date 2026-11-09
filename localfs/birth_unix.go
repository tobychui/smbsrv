//go:build unix && !darwin

package localfs

import (
	"os"
	"time"
)

// birthTime is unknown: stat has no creation time here (only statx(2) on a
// recent Linux has one, and not every file system records it). The server
// then reports the modification time.
func birthTime(fi os.FileInfo) time.Time { return time.Time{} }
