# Multiple reader workspaces

`s3disk mount-set` is a bounded, declarative supervisor for machines which
consume several independent workspaces. It runs one ordinary read-only mount
lifecycle per configuration entry inside one process. It does not merge paths,
share trust domains, or create a union filesystem.

## Configuration

The command accepts one versioned JSON file:

```json
{
  "version": 1,
  "mounts": [
    {
      "name": "project-a",
      "handoff": "/secure/project-a.handoff",
      "mountpoint": "/mnt/project-a",
      "state_dir": "/var/lib/s3disk/reader",
      "cache_dir": "/var/cache/s3disk",
      "macos_backend": "auto",
      "poll_interval": "1s",
      "poll_timeout": "2m"
    }
  ]
}
```

`cache_dir`, `macos_backend`, `poll_interval`, and `poll_timeout` are optional.
The macOS backend is `auto`, `vfs`, or `fskit`; an omitted value is `auto`.
Polling defaults to the same one-second interval and two-minute complete-attempt
timeout as `s3disk mount`. Every path must be absolute. Names are 1 through 64
ASCII
letters, digits, dots, underscores, or hyphens and must begin with a letter or
digit. The file is limited to 1 MiB and 128 entries.

The configuration is local security state. It must be a regular, non-symlink,
single-link file owned by the current process identity with exact `0600`
permissions below a hierarchy accepted by `ValidatePrivateSecretFile`. Unknown
or duplicate JSON members and trailing JSON values are rejected. The file is
read once; changes require a controlled restart.

Mountpoints must exist and be distinct. The supervisor resolves symlinks before
checking that no mountpoint contains or overlaps another mountpoint, state or
cache base, handoff, or the configuration. It fully authenticates every handoff
before starting FUSE and rejects two entries that identify the same repository
share, even if the handoff bytes were copied to different paths. Distinct
shares may use common state and cache bases because the CLI derives separate
repository/share subdirectories.

## Lifecycle

Run the set in the foreground:

```sh
s3disk mount-set --config /secure/s3disk-mounts.json
```

Status and warning lines from a child are prefixed with its configured name. If
one child reports a terminal error, the supervisor cancels every peer, waits for
their bounded automatic-unmount lifecycles, and returns the named failure. A
clean lifecycle end, including authorization expiry, is reported and does not
remove later-expiring workspaces. The command exits successfully after all
workspaces have ended or after graceful process-context cancellation.

The required Linux and macOS integration gates create two independent real
FUSE mounts under one supervisor, read distinct content through both mounts,
then cancel the supervisor and require both lifecycles to unmount before they
return. This is a functional concurrency gate, not a long-duration soak.

Run the command below the platform service manager for restart policy, resource
limits, log shipping, and boot ordering. Do not configure a service manager to
kill the process before the mount package's default 30-second automatic-unmount
window has elapsed. A busy or uninterruptible OS unmount can still enter
`stop_failed`; the process then returns an error so operators do not mistake a
remaining mount for a clean stop.

## Deliberate boundaries

- Publisher workspaces still use one `share publish` or `share resume` process
  each. `mount-set` is reader-only.
- There is no union mount or common root. Each workspace keeps its own
  mountpoint, encryption key, signed reference, expiry, watermark, and cache
  namespace.
- There is no configuration hot reload or automatic per-child restart. A
  restart re-runs the complete all-entry preflight before mounting anything.
- Process-level isolation is weaker than separate service identities. Use
  separate `s3disk mount` processes when local-user or resource-failure
  isolation matters more than operational convenience.
