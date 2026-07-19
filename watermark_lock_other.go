//go:build !darwin && !dragonfly && !freebsd && !linux && !netbsd && !openbsd && !windows

package s3disk

import (
	"context"
	"sync"
)

var fallbackWatermarkLocks sync.Map

func lockWatermarkFile(_ context.Context, path string) (func() error, error) {
	value, _ := fallbackWatermarkLocks.LoadOrStore(path, new(sync.Mutex))
	lock := value.(*sync.Mutex)
	lock.Lock()
	return func() error {
		lock.Unlock()
		return nil
	}, nil
}
