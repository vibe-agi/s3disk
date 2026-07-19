package publisherstate

import "errors"

var (
	ErrInvalidRecoveryKey   = errors.New("publisherstate: invalid recovery key")
	ErrInvalidKeyID         = errors.New("publisherstate: invalid protector key ID")
	ErrInvalidBinding       = errors.New("publisherstate: invalid caller binding")
	ErrInvalidEnvelope      = errors.New("publisherstate: invalid sealed envelope")
	ErrAuthenticationFailed = errors.New("publisherstate: envelope authentication failed")
	ErrResourceLimit        = errors.New("publisherstate: resource limit exceeded")
	ErrProtectorUnavailable = errors.New("publisherstate: protector is not configured")
	ErrProtectorConflict    = errors.New("publisherstate: protector key ID conflict")
)
