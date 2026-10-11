package config

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/pelletier/go-toml/v2"
)

// CredentialsFileName is the file next to config.toml that holds the proxy
// password (ADR-011). It is kept out of config.toml so the config can be
// shared as is.
const CredentialsFileName = "credentials.toml"

const credentialsHeader = "# gostpx: пароль прокси (ADR-011). Не пересылать и не коммитить.\n" +
	"# Меняется командой gostpx set; файл доступен только владельцу.\n"

type credentialsFile struct {
	Password string `toml:"password"`
}

// CredentialsPath returns the credentials file path for the given config path.
func CredentialsPath(configPath string) string {
	return filepath.Join(filepath.Dir(configPath), CredentialsFileName)
}

var osChmod = os.Chmod

// LoadPassword reads the proxy password. A missing file means no password.
// Permissions wider than 0600 are tightened.
func LoadPassword(path string) (string, error) {
	data, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return "", nil
	}
	if err != nil {
		return "", fmt.Errorf("read credentials: %w", err)
	}
	if info, err := os.Stat(path); err == nil && info.Mode().Perm()&0o077 != 0 {
		if err := osChmod(path, 0o600); err != nil {
			return "", fmt.Errorf("tighten credentials permissions: %w", err)
		}
	}

	data = bytes.TrimPrefix(data, []byte("\xef\xbb\xbf"))
	var cf credentialsFile
	dec := toml.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&cf); err != nil {
		var decodeErr *toml.DecodeError
		if errors.As(err, &decodeErr) {
			row, col := decodeErr.Position()
			return "", fmt.Errorf("credentials line %d, col %d: %s", row, col, decodeErr.String())
		}
		return "", fmt.Errorf("decode credentials: %w", err)
	}
	return cf.Password, nil
}

// SavePassword writes the proxy password with 0600 permissions. An empty
// password removes the file, so a proxy without auth never receives an old
// password.
func SavePassword(path, password string) error {
	if password == "" {
		if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("remove credentials: %w", err)
		}
		return nil
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return fmt.Errorf("create config directory: %w", err)
	}

	body, err := toml.Marshal(credentialsFile{Password: password})
	if err != nil {
		return fmt.Errorf("encode credentials: %w", err)
	}
	data := append([]byte(credentialsHeader), body...)

	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return fmt.Errorf("write credentials: %w", err)
	}
	if err := os.Rename(tmp, path); err != nil {
		_ = os.Remove(tmp)
		return fmt.Errorf("rename credentials: %w", err)
	}
	return nil
}
