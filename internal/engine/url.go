package engine

import (
	"fmt"
	"net/url"
	"regexp"
	"strconv"
	"strings"

	"github.com/losoph/gostpx/internal/config"
)

var (
	// urlPasswordRegex matches :password@ in URLs for string sanitization
	urlPasswordRegex = regexp.MustCompile(`://([^:]+):([^@]+)@`)
)

// MaskURL returns a copy of the URL string with the password replaced by "***".
func MaskURL(u *url.URL) string {
	if u == nil {
		return ""
	}
	s := u.String()
	if u.User != nil {
		if _, hasPass := u.User.Password(); hasPass {
			rawUserInfo := u.User.String() + "@"
			maskedUserInfo := u.User.Username() + ":***@"
			s = strings.Replace(s, rawUserInfo, maskedUserInfo, 1)
		}
	}
	return s
}

// MaskURLString masks credentials in a raw URL string.
func MaskURLString(raw string) string {
	if raw == "" {
		return ""
	}
	u, err := url.Parse(raw)
	if err == nil && u.Scheme != "" && u.Host != "" {
		return MaskURL(u)
	}
	// Fallback regex replacement
	return urlPasswordRegex.ReplaceAllString(raw, `://$1:***@`)
}

type sanitizedError struct {
	err error
	msg string
}

func (s *sanitizedError) Error() string {
	return s.msg
}

func (s *sanitizedError) Unwrap() error {
	return s.err
}

// SanitizeError returns an error where any occurrences of raw URL or plain secret are masked,
// while preserving the original error chain for errors.Is and errors.As.
func SanitizeError(err error, plainSecret string) error {
	if err == nil {
		return nil
	}
	msg := err.Error()
	if plainSecret != "" {
		msg = strings.ReplaceAll(msg, plainSecret, "***")
	}
	msg = MaskURLString(msg)
	return &sanitizedError{
		err: err,
		msg: msg,
	}
}

// BuildProxyURL constructs a *url.URL from ProxyConfig and the resolved plain password.
func BuildProxyURL(cfg config.ProxyConfig, plainSecret string) (*url.URL, error) {
	if cfg.Host == "" {
		return nil, fmt.Errorf("proxy host is required")
	}
	port := cfg.Port
	if port <= 0 || port > 65535 {
		port = 1080
	}

	scheme := cfg.Type
	if scheme == "" {
		scheme = config.ProxyTypeSOCKS5
	}

	hostPort := cfg.Host + ":" + strconv.Itoa(port)
	u := &url.URL{
		Scheme: scheme,
		Host:   hostPort,
	}

	if cfg.User != "" || plainSecret != "" {
		if plainSecret != "" {
			u.User = url.UserPassword(cfg.User, plainSecret)
		} else {
			u.User = url.User(cfg.User)
		}
	}

	return u, nil
}

// ParseProxyURL parses a proxy URL string (e.g. from `gostpx set <url>`)
// into components suitable for ProxyConfig and extracting the plain password.
func ParseProxyURL(rawURL string) (proxyCfg config.ProxyConfig, plainPassword string, err error) {
	u, err := url.Parse(rawURL)
	if err != nil {
		return proxyCfg, "", fmt.Errorf("invalid proxy URL %q: %w", MaskURLString(rawURL), err)
	}

	if u.Scheme == "" {
		return proxyCfg, "", fmt.Errorf("missing protocol scheme in URL %q", MaskURLString(rawURL))
	}

	switch u.Scheme {
	case "socks5", "http", "ssh":
		proxyCfg.Type = u.Scheme
	default:
		return proxyCfg, "", fmt.Errorf("unsupported protocol scheme %q", u.Scheme)
	}

	host := u.Hostname()
	if host == "" {
		return proxyCfg, "", fmt.Errorf("missing host in URL %q", MaskURL(u))
	}
	proxyCfg.Host = host

	portStr := u.Port()
	if portStr != "" {
		p, err := strconv.Atoi(portStr)
		if err != nil || p < 1 || p > 65535 {
			return proxyCfg, "", fmt.Errorf("invalid port %q in URL %q", portStr, MaskURL(u))
		}
		proxyCfg.Port = p
	} else {
		// Default ports by scheme
		switch proxyCfg.Type {
		case "http":
			proxyCfg.Port = 8080
		case "ssh":
			proxyCfg.Port = 22
		default:
			proxyCfg.Port = 1080
		}
	}

	if u.User != nil {
		proxyCfg.User = u.User.Username()
		pass, hasPass := u.User.Password()
		if hasPass {
			plainPassword = pass
		}
	}

	return proxyCfg, plainPassword, nil
}
