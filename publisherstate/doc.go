// Package publisherstate provides a small cryptographic sealing boundary for
// sensitive publisher recovery state.
//
// A Protector authenticates its envelope format, key identity, and a
// caller-supplied binding while encrypting plaintext with a key derived from a
// 256-bit RecoveryKey. It does not read or write files, choose a storage path,
// validate filesystem permissions, manage a KMS, or retain previous versions.
//
// In particular, a valid envelope has confidentiality and integrity but no
// freshness. An attacker or faulty backup system which can replace storage may
// replay an older valid envelope. Applications must provide their own durable
// monotonic revision, compare-and-swap, rollback detection, locking, backup,
// and lifecycle policy around this package.
package publisherstate
