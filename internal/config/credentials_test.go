package config

import (
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestCredentialsRoundTrip(t *testing.T) {
	path := filepath.Join(t.TempDir(), CredentialsFileName)

	if pw, err := LoadPassword(path); err != nil || pw != "" {
		t.Fatalf("missing file: got (%q, %v), want (\"\", nil)", pw, err)
	}

	const secret = `p@ss "quoted" \ back`
	if err := SavePassword(path, secret); err != nil {
		t.Fatalf("save: %v", err)
	}
	pw, err := LoadPassword(path)
	if err != nil || pw != secret {
		t.Fatalf("load: got (%q, %v), want %q", pw, err, secret)
	}

	if runtime.GOOS != "windows" {
		info, err := os.Stat(path)
		if err != nil {
			t.Fatal(err)
		}
		if perm := info.Mode().Perm(); perm != 0o600 {
			t.Errorf("perm = %o, want 600", perm)
		}
	}

	if err := SavePassword(path, ""); err != nil {
		t.Fatalf("clear: %v", err)
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Errorf("file still exists after empty password: %v", err)
	}
	if err := SavePassword(path, ""); err != nil {
		t.Errorf("clearing a missing file must not fail: %v", err)
	}
}

func TestLoadPasswordBOMAndPerms(t *testing.T) {
	path := filepath.Join(t.TempDir(), CredentialsFileName)
	if err := os.WriteFile(path, []byte("\xef\xbb\xbfpassword = \"x\"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	pw, err := LoadPassword(path)
	if err != nil || pw != "x" {
		t.Fatalf("got (%q, %v), want \"x\"", pw, err)
	}
	if runtime.GOOS != "windows" {
		info, _ := os.Stat(path)
		if perm := info.Mode().Perm(); perm != 0o600 {
			t.Errorf("perm = %o, want tightened to 600", perm)
		}
	}
}

func TestLoadPasswordBroken(t *testing.T) {
	dir := t.TempDir()
	cases := map[string]string{
		"syntax":  "password = \"unterminated\n",
		"unknown": "password = \"x\"\nuser = \"y\"\n",
	}
	for name, body := range cases {
		path := filepath.Join(dir, name+".toml")
		if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := LoadPassword(path); err == nil {
			t.Errorf("%s: expected error", name)
		}
	}
}

func TestLoadPassword_TightenPermissionsError(t *testing.T) {
	origChmod := osChmod
	defer func() { osChmod = origChmod }()

	path := filepath.Join(t.TempDir(), CredentialsFileName)
	if err := os.WriteFile(path, []byte("password = \"secret\"\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	osChmod = func(name string, mode os.FileMode) error {
		return errors.New("permission denied")
	}

	_, err := LoadPassword(path)
	if err == nil || !strings.Contains(err.Error(), "tighten credentials permissions") {
		t.Fatalf("expected tighten credentials permissions error, got: %v", err)
	}
}
