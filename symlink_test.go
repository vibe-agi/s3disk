package s3disk

import (
	"errors"
	"testing"
)

func TestValidateSafeSymlink(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name     string
		linkPath string
		target   string
		unsafe   bool
	}{
		{name: "sibling", linkPath: "a/link", target: "file"},
		{name: "parent within root", linkPath: "a/b/link", target: "../../file"},
		{name: "root escape", linkPath: "a/link", target: "../../file", unsafe: true},
		{name: "absolute", linkPath: "link", target: "/etc/passwd", unsafe: true},
		{name: "windows drive", linkPath: "link", target: "C:/secret", unsafe: true},
		{name: "windows separators", linkPath: "a/link", target: `..\\secret`, unsafe: true},
		{name: "empty", linkPath: "link", target: "", unsafe: true},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			err := validateSafeSymlink(test.linkPath, test.target)
			if test.unsafe && !errors.Is(err, ErrUnsafeSymlink) {
				t.Fatalf("error = %v, want ErrUnsafeSymlink", err)
			}
			if !test.unsafe && err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
		})
	}
}
