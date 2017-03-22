package sodium

import (
	"testing"
	"strings"
)

func TestSodiumVersion(t *testing.T) {
	str := VersionString()
	maj := LibraryVersionMajor()
	min := LibraryVersionMinor()
	slm := LibraryMinimal()

	t.Logf("Sodium version: %s\n", str)
	t.Logf("Sodium library version: %v.%v", maj, min)
	t.Logf("Minimal: %v", slm)

	version := strings.Split(VersionString(), ".")
	if len(version) != 3 {
		t.Error("Sodium version should consist of three components")
	}

	if maj <= 0 || maj > 100 {
		t.Errorf("Suspicious library version major: %v", maj)
	}

	if min <= 0 || min > 100 {
		t.Errorf("Suspicious library version minor: %v", min)
	}
}
