//go:build linux || darwin || freebsd

package localfs

import "golang.org/x/sys/unix"

// diskUsage returns the size and the free bytes of the disk holding dir, as
// an unprivileged user may use them.
func diskUsage(dir string) (total, free uint64, err error) {
	var st unix.Statfs_t
	if err := unix.Statfs(dir, &st); err != nil {
		return 0, 0, err
	}
	bsize := int64(st.Bsize)
	blocks, avail := int64(st.Blocks), int64(st.Bavail)
	if bsize <= 0 || blocks <= 0 {
		return 0, 0, nil
	}
	if avail < 0 {
		avail = 0
	}
	return uint64(blocks) * uint64(bsize), uint64(avail) * uint64(bsize), nil
}
