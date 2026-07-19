package mount

import (
	"errors"
	"testing"

	"github.com/vibe-agi/s3disk"
)

func TestValidateReadOnlySecurityDefaultsAndExplicitOptOuts(t *testing.T) {
	t.Parallel()
	for _, test := range []struct {
		name        string
		status      s3disk.ConsumerSecurityStatus
		options     Options
		want        error
		wantAlso    error
		shouldAllow bool
	}{
		{
			name: "durable safe unsigned consumer",
			status: s3disk.ConsumerSecurityStatus{
				DurableWatermarkConfigured: true,
				SymlinkPolicy:              s3disk.SymlinkRejectExternal,
			},
			shouldAllow: true,
		},
		{
			name:   "missing durable watermark",
			status: s3disk.ConsumerSecurityStatus{SymlinkPolicy: s3disk.SymlinkRejectExternal},
			want:   ErrDurableWatermarkRequired,
		},
		{
			name:   "explicit missing watermark opt-out",
			status: s3disk.ConsumerSecurityStatus{SymlinkPolicy: s3disk.SymlinkRejectExternal},
			options: Options{
				DangerouslyAllowMountWithoutDurableWatermark: true,
			},
			shouldAllow: true,
		},
		{
			name: "preserved symlink",
			status: s3disk.ConsumerSecurityStatus{
				DurableWatermarkConfigured: true,
				SymlinkPolicy:              s3disk.SymlinkPreserve,
			},
			want: ErrSymlinkPreserveUnsafe,
		},
		{
			name: "explicit preserved symlink opt-out",
			status: s3disk.ConsumerSecurityStatus{
				DurableWatermarkConfigured: true,
				SymlinkPolicy:              s3disk.SymlinkPreserve,
			},
			options: Options{
				DangerouslyAllowMountWithPreservedSymlinks: true,
			},
			shouldAllow: true,
		},
		{
			name: "both unsafe defaults",
			status: s3disk.ConsumerSecurityStatus{
				SymlinkPolicy: s3disk.SymlinkPreserve,
			},
			want:     ErrDurableWatermarkRequired,
			wantAlso: ErrSymlinkPreserveUnsafe,
		},
		{
			name: "one opt-out cannot waive the other risk",
			status: s3disk.ConsumerSecurityStatus{
				SymlinkPolicy: s3disk.SymlinkPreserve,
			},
			options: Options{
				DangerouslyAllowMountWithoutDurableWatermark: true,
			},
			want: ErrSymlinkPreserveUnsafe,
		},
		{
			name: "preserved symlink opt-out cannot waive watermark risk",
			status: s3disk.ConsumerSecurityStatus{
				SymlinkPolicy: s3disk.SymlinkPreserve,
			},
			options: Options{
				DangerouslyAllowMountWithPreservedSymlinks: true,
			},
			want: ErrDurableWatermarkRequired,
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			err := validateReadOnlySecurity(test.status, test.options)
			if test.shouldAllow {
				if err != nil {
					t.Fatalf("validateReadOnlySecurity error = %v", err)
				}
				return
			}
			if !errors.Is(err, test.want) {
				t.Fatalf("validateReadOnlySecurity error = %v, want errors.Is(..., %v)", err, test.want)
			}
			if test.wantAlso != nil && !errors.Is(err, test.wantAlso) {
				t.Fatalf("validateReadOnlySecurity error = %v, also want errors.Is(..., %v)", err, test.wantAlso)
			}
		})
	}
}
