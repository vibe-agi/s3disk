package s3disk

import "reflect"

// ConsumerSecurityStatus reports the immutable security-relevant configuration
// of a Consumer without performing Store or local-state I/O. A configured
// WatermarkStore is described as durable because durability is part of that
// interface's contract; this method does not probe the implementation or make
// the watermark an offline snapshot cache.
type ConsumerSecurityStatus struct {
	// DurableWatermarkConfigured reports configuration under the
	// WatermarkStore durability contract; it does not probe custom code.
	DurableWatermarkConfigured bool
	SymlinkPolicy              SymlinkPolicy
	// ReferenceAuthenticationConfigured reports that every fetched channel
	// reference must pass the configured verifier. It does not report that a
	// reference has already been fetched or adopted.
	ReferenceAuthenticationConfigured bool
}

// SecurityStatus returns the Consumer's immutable security configuration. It
// is safe to call concurrently with refreshes and lazy reads.
func (consumer *Consumer) SecurityStatus() ConsumerSecurityStatus {
	if consumer == nil {
		return ConsumerSecurityStatus{}
	}
	return ConsumerSecurityStatus{
		DurableWatermarkConfigured:        interfaceDependencyConfigured(consumer.watermarks),
		SymlinkPolicy:                     consumer.symlinkPolicy,
		ReferenceAuthenticationConfigured: interfaceDependencyConfigured(consumer.referenceVerifier),
	}
}

// interfaceDependencyConfigured distinguishes an interface containing a typed
// nil from a usable dependency. Constructors reject typed nils; the defensive
// check here keeps read-only status inspection fail-closed for a zero or
// directly constructed Consumer.
func interfaceDependencyConfigured(value any) bool {
	if value == nil {
		return false
	}
	reflected := reflect.ValueOf(value)
	switch reflected.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
		return !reflected.IsNil()
	default:
		return true
	}
}
