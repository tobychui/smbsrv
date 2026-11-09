//go:build !windows

package smbsrv

import (
	"errors"
	"syscall"
)

func isNotDirectory(err error) bool { return errors.Is(err, syscall.ENOTDIR) }
func isDiskFull(err error) bool {
	return errors.Is(err, syscall.ENOSPC) || errors.Is(err, syscall.EDQUOT)
}
func isNotEmpty(err error) bool { return errors.Is(err, syscall.ENOTEMPTY) }
