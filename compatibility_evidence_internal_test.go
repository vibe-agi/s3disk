package s3disk

import "testing"

func TestPreReleaseCompatibilityProbePayloadDomainRemainsVersionOne(t *testing.T) {
	t.Parallel()
	if compatibilityProbePayloadDomain != "s3disk-store-probe-v1" {
		t.Fatalf("pre-release compatibility payload domain = %q, want v1 until the first public release", compatibilityProbePayloadDomain)
	}
}
