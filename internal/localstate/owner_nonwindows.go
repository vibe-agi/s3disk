//go:build !windows && !plan9

package localstate

import (
	"os"
	"syscall"
)

func trustedWatermarkPathOwner(info os.FileInfo) bool {
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return false
	}
	uid := uint64(stat.Uid)
	return uid == 0 || uid == uint64(os.Geteuid())
}
