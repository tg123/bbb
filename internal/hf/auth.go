package hf

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

func authToken() (string, error) {
	if disabled, err := strconv.ParseBool(os.Getenv("HF_HUB_DISABLE_IMPLICIT_TOKEN")); err == nil && disabled {
		return "", nil
	}
	for _, name := range []string{"HF_TOKEN", "HUGGING_FACE_HUB_TOKEN"} {
		if token := strings.TrimSpace(os.Getenv(name)); token != "" {
			return token, nil
		}
	}

	tokenPath := os.Getenv("HF_TOKEN_PATH")
	if tokenPath == "" {
		home := os.Getenv("HF_HOME")
		if home == "" {
			cache := os.Getenv("XDG_CACHE_HOME")
			if cache == "" {
				userHome, err := os.UserHomeDir()
				if err != nil {
					return "", nil
				}
				cache = filepath.Join(userHome, ".cache")
			}
			home = filepath.Join(cache, "huggingface")
		}
		tokenPath = filepath.Join(home, "token")
	}
	if tokenPath == "~" || strings.HasPrefix(tokenPath, "~/") || strings.HasPrefix(tokenPath, `~\`) {
		home, err := os.UserHomeDir()
		if err != nil {
			return "", fmt.Errorf("expand Hugging Face token path: %w", err)
		}
		tokenPath = filepath.Join(home, strings.TrimLeft(tokenPath[1:], `/\`))
	}
	data, err := os.ReadFile(tokenPath)
	if errors.Is(err, os.ErrNotExist) {
		return "", nil
	}
	if err != nil {
		return "", fmt.Errorf("read Hugging Face token: %w", err)
	}
	return strings.TrimSpace(string(data)), nil
}

func isHubURL(u *url.URL) bool {
	return u.Scheme == "https" && strings.EqualFold(u.Hostname(), "huggingface.co") &&
		(u.Port() == "" || u.Port() == "443")
}

func newRequest(ctx context.Context, method, rawURL string) (*http.Request, error) {
	req, err := http.NewRequestWithContext(ctx, method, rawURL, nil)
	if err != nil {
		return nil, err
	}
	if isHubURL(req.URL) {
		token, err := authToken()
		if err != nil {
			return nil, err
		}
		if token != "" {
			req.Header.Set("Authorization", "Bearer "+token)
		}
	}
	return req, nil
}

func hubClient(base *http.Client) *http.Client {
	client := *base
	client.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		var err error
		if base.CheckRedirect != nil {
			err = base.CheckRedirect(req, via)
		} else if len(via) >= 10 {
			err = errors.New("stopped after 10 redirects")
		}
		// Go forwards Authorization to subdomains and HTTPS-to-HTTP redirects.
		// Enforce the HTTPS Hub restriction after custom policies copy headers.
		if !isHubURL(req.URL) {
			req.Header.Del("Authorization")
		}
		return err
	}
	return &client
}
