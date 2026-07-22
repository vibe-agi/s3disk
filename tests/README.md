# Tests

`blackbox/` contains tests that exercise s3disk only through its exported API.
They live outside the root package so the repository root stays focused on the
library implementation and its white-box unit tests.

Tests that intentionally verify unexported invariants remain beside the package
they cover. Moving those tests here would require exposing implementation
details as public API.
