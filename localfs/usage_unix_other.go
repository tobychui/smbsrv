//go:build unix && !linux && !darwin && !freebsd

package localfs

import "errors"

func diskUsage(dir string) (total, free uint64, err error) {
	return 0, 0, errors.New("localfs: disk usage is not known on this system")
}
