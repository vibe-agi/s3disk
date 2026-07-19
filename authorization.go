package s3disk

import "time"

// AuthorizationExpirySource optionally reports the earliest known time at
// which authorization required for a future ObjectReader.Get may expire. The
// method must be a local, non-blocking state inspection and must perform no
// network or filesystem I/O. A false result means no finite deadline is known.
//
// This deadline is only a conservative local auto-unmount and UX signal. It is
// not an access-control decision: the backing S3-compatible object store must
// reject expired presigned requests, and expiration cannot revoke bytes a
// client has already read or cached. Composite readers must report the earliest
// authorization expiry that can prevent them from serving a future Get.
type AuthorizationExpirySource interface {
	AuthorizationExpiry() (time.Time, bool)
}

// AuthorizationExpiry returns the earliest authorization deadline exposed by
// this repository's ObjectReader without performing I/O.
func (repository *Repository) AuthorizationExpiry() (time.Time, bool) {
	if repository == nil || !interfaceDependencyConfigured(repository.reader) {
		return time.Time{}, false
	}
	source, ok := repository.reader.(AuthorizationExpirySource)
	if !ok || !interfaceDependencyConfigured(source) {
		return time.Time{}, false
	}
	expiresAt, known := source.AuthorizationExpiry()
	if !known || expiresAt.IsZero() {
		return time.Time{}, false
	}
	return expiresAt, true
}

// AuthorizationExpiry forwards the Consumer repository's earliest known
// authorization deadline without performing Store, network, or local-state
// I/O. See AuthorizationExpirySource for the security limits of this signal.
func (consumer *Consumer) AuthorizationExpiry() (time.Time, bool) {
	if consumer == nil || consumer.repository == nil {
		return time.Time{}, false
	}
	return consumer.repository.AuthorizationExpiry()
}
