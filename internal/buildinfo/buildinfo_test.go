package buildinfo

import (
	"regexp"
	"runtime"
	"strings"
	"testing"
)

var semver = regexp.MustCompile(`^\d+\.\d+\.\d+$`)

func TestVersionIsSemver(t *testing.T) {
	if !semver.MatchString(Version) {
		t.Errorf("Version = %q, want MAJOR.MINOR.PATCH", Version)
	}
}

// TestDerivationVersionIsFrozen guards the compatibility contract: this value
// may only change together with a deliberate, documented break of every
// previously generated password.
func TestDerivationVersionIsFrozen(t *testing.T) {
	if DerivationVersion != "pypassgen-1.3.5" {
		t.Fatalf("DerivationVersion = %q — changing it breaks every existing password", DerivationVersion)
	}
}

func TestShort(t *testing.T) {
	want := Name + " " + Version
	if got := Short(); got != want {
		t.Errorf("Short() = %q, want %q", got, want)
	}
}

func TestVersionString(t *testing.T) {
	s := VersionString()
	for _, want := range []string{Name, Version, DerivationVersion, runtime.Version(), runtime.GOOS, runtime.GOARCH} {
		if !strings.Contains(s, want) {
			t.Errorf("VersionString() missing %q:\n%s", want, s)
		}
	}
	if lines := strings.Count(s, "\n"); lines != 2 {
		t.Errorf("VersionString() should be 3 lines, got %d newlines", lines)
	}
}
