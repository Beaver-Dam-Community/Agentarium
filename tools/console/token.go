package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"sync"
	"time"
)

// refreshBefore is how long before exp a cached token is replaced.
const refreshBefore = 2 * time.Minute

// tokenTimeout bounds one run of the token command. With the identity
// client timeout it stays well inside the local server's WriteTimeout.
const tokenTimeout = 30 * time.Second

// tokenSource runs the token command and keeps the Google ID token in memory
// until shortly before its exp. The token is never logged, written to disk
// or returned to the browser.
type tokenSource struct {
	argv []string
	now  func() time.Time
	// run executes argv and returns its stdout; tests replace it.
	run func(ctx context.Context, argv []string) ([]byte, error)

	mu       sync.Mutex
	token    string
	exp, iat time.Time
	// refreshing is closed when the refresh in flight ends; refreshErr is
	// that refresh's error. The command runs outside mu, so a caller whose
	// cached token is still usable never waits for it.
	refreshing chan struct{}
	refreshErr error
}

func newTokenSource(command string) (*tokenSource, error) {
	argv := strings.Fields(command)
	if len(argv) == 0 {
		return nil, errors.New("-token-command is empty")
	}
	return &tokenSource{argv: argv, now: time.Now, run: runCommand}, nil
}

// runCommand executes argv directly (no shell). Its stderr goes to the
// operator's terminal so prompts and errors stay visible; stdout, which
// holds the token, is captured.
func runCommand(ctx context.Context, argv []string) ([]byte, error) {
	cmd := exec.CommandContext(ctx, argv[0], argv[1:]...)
	var out bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("token command %q failed: %w", argv[0], err)
	}
	return out.Bytes(), nil
}

// usable reports whether the cached token is valid for at least
// refreshBefore and, with maxAge > 0, was issued within maxAge. mu is held.
func (s *tokenSource) usable(now time.Time, maxAge time.Duration) bool {
	return s.token != "" && now.Add(refreshBefore).Before(s.exp) && (maxAge <= 0 || now.Sub(s.iat) < maxAge)
}

// Token returns a cached token valid for at least refreshBefore. With
// maxAge > 0 it also requires the token to have been issued (iat) within
// maxAge, running the command again otherwise; identity's approval POST
// needs a token issued within 5 minutes. Concurrent callers share one run of
// the command (single flight); a caller that waited for another caller's
// refresh does not start a second one.
func (s *tokenSource) Token(ctx context.Context, maxAge time.Duration) (string, error) {
	s.mu.Lock()
	if s.usable(s.now(), maxAge) {
		tok := s.token
		s.mu.Unlock()
		return tok, nil
	}
	if ch := s.refreshing; ch != nil {
		s.mu.Unlock()
		select {
		case <-ch:
		case <-ctx.Done():
			return "", ctx.Err()
		}
		s.mu.Lock()
		defer s.mu.Unlock()
		return s.result(maxAge)
	}
	ch := make(chan struct{})
	s.refreshing = ch
	s.mu.Unlock()

	// The refresh is shared, so one caller's cancellation does not cut it.
	cctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), tokenTimeout)
	tok, exp, iat, err := s.fetch(cctx)
	cancel()

	s.mu.Lock()
	defer s.mu.Unlock()
	if err == nil {
		s.token, s.exp, s.iat = tok, exp, iat
	}
	s.refreshErr = err
	s.refreshing = nil
	close(ch)
	return s.result(maxAge)
}

// result answers after a refresh: the cached token if it now satisfies
// maxAge, else the refresh error or a stale-token error. mu is held.
func (s *tokenSource) result(maxAge time.Duration) (string, error) {
	now := s.now()
	if s.usable(now, maxAge) {
		return s.token, nil
	}
	if s.refreshErr != nil {
		return "", s.refreshErr
	}
	if s.token != "" && maxAge > 0 && now.Sub(s.iat) >= maxAge {
		// The command returned a token issued too long ago (gcloud can
		// return its own cached token); identity would reject it.
		return "", fmt.Errorf("the token command returned an ID token issued %s ago, older than %s; run gcloud auth login and try again",
			now.Sub(s.iat).Round(time.Second), maxAge)
	}
	return "", errors.New("the token command returned a token that expires too soon")
}

// fetch runs the command and parses the token it prints.
func (s *tokenSource) fetch(ctx context.Context) (string, time.Time, time.Time, error) {
	out, err := s.run(ctx, s.argv)
	if err != nil {
		return "", time.Time{}, time.Time{}, err
	}
	tok := strings.TrimSpace(string(out))
	exp, iat, err := jwtTimes(tok)
	if err != nil {
		return "", time.Time{}, time.Time{}, fmt.Errorf("token command output: %w", err)
	}
	if !s.now().Before(exp) {
		return "", time.Time{}, time.Time{}, errors.New("token command returned an expired token")
	}
	return tok, exp, iat, nil
}

// jwtTimes reads exp and iat from a JWT payload without verifying it; the
// console only needs them to schedule refreshes, identity verifies the token.
// Errors never include the token.
func jwtTimes(tok string) (exp, iat time.Time, err error) {
	parts := strings.Split(tok, ".")
	if len(parts) != 3 {
		return time.Time{}, time.Time{}, errors.New("not a JWT")
	}
	for _, p := range parts {
		if _, err := base64.RawURLEncoding.DecodeString(p); err != nil || p == "" {
			return time.Time{}, time.Time{}, errors.New("JWT segment is not base64url")
		}
	}
	raw, _ := base64.RawURLEncoding.DecodeString(parts[1])
	var claims struct {
		Exp int64 `json:"exp"`
		Iat int64 `json:"iat"`
	}
	if err := json.Unmarshal(raw, &claims); err != nil {
		return time.Time{}, time.Time{}, errors.New("JWT payload is not JSON")
	}
	if claims.Exp == 0 {
		return time.Time{}, time.Time{}, errors.New("JWT has no exp")
	}
	return time.Unix(claims.Exp, 0), time.Unix(claims.Iat, 0), nil
}
