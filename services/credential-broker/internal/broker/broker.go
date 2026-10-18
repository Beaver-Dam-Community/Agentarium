// Package broker resolves only registered adapter/operation bindings for planned
// attempts. The caller never supplies a Secret Manager resource or version.
package broker

import (
	"context"
	"errors"
	"regexp"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/google/uuid"
)

var ErrUnavailable = errors.New("credential unavailable")
var resourcePattern = regexp.MustCompile(`^projects/[A-Za-z0-9_-]+/secrets/[A-Za-z0-9_-]+$`)
var versionPattern = regexp.MustCompile(`^[0-9]+$`)

const MaxHeaderBytes = 2048
const CacheLifetime = 60 * time.Second

type Request struct {
	AttemptID string `json:"attempt_id"`
	AdapterID string `json:"adapter_id"`
	Binding   string `json:"credential_binding"`
}
type Response struct {
	Version     string    `json:"secret_version"`
	HeaderName  string    `json:"header_name"`
	HeaderValue string    `json:"header_value"`
	ExpiresAt   time.Time `json:"expires_at"`
}
type Binding struct{ Resource, Version, HeaderName, Format string }
type Repository interface {
	Resolve(context.Context, string, string, Request) (Binding, error)
}
type Secrets interface {
	Access(context.Context, string) ([]byte, error)
}

// Metadata contains identifiers only. No secret value or authorization header
// is passed to operational logging. This is not a new AuditEvent registry type.
type Metadata struct{ Resource, Version string }
type entry struct {
	value   []byte
	expires time.Time
}
type Service struct {
	Repo    Repository
	Secrets Secrets
	Observe func(Metadata)
	// ObserveFailure receives only a fixed local category, never provider error
	// text, request fields, resource identifiers, or secret values.
	ObserveFailure func(string)
	Now            func() time.Time
	mu             sync.Mutex
	cache          map[string]entry
}

func (s *Service) unavailable(category string) error {
	if s.ObserveFailure != nil {
		s.ObserveFailure(category)
	}
	return ErrUnavailable
}

func (s *Service) now() time.Time {
	if s.Now != nil {
		return s.Now()
	}
	return time.Now()
}
func validHeaderName(name string) bool {
	if name == "" {
		return false
	}
	for _, r := range name {
		if r > 127 || !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || strings.ContainsRune("!#$%&'*+-.^_`|~", r)) {
			return false
		}
	}
	return true
}
func (b Binding) valid() bool {
	return resourcePattern.MatchString(b.Resource) && versionPattern.MatchString(b.Version) && strings.Trim(b.Version, "0") != "" && validHeaderName(b.HeaderName) && (b.Format == "raw" || b.Format == "bearer")
}
func (r Request) valid() bool {
	u, e := uuid.Parse(r.AttemptID)
	return e == nil && u != uuid.Nil && u.String() == r.AttemptID && r.AdapterID != "" && r.Binding != ""
}
func safeHeader(value []byte) bool {
	if len(value) == 0 || !utf8.Valid(value) {
		return false
	}
	for _, b := range value {
		if b < 32 || b == 127 {
			return false
		}
	}
	return true
}
func (s *Service) cached(key string) (entry, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.now()
	for k, e := range s.cache {
		if !now.Before(e.expires) {
			clear(e.value)
			delete(s.cache, k)
		}
	}
	e, ok := s.cache[key]
	e.value = append([]byte(nil), e.value...)
	return e, ok
}
func (s *Service) put(key string, e entry) time.Time {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.cache == nil {
		s.cache = map[string]entry{}
	}
	if len(s.cache) >= 1024 {
		var oldest string
		var expiry time.Time
		for k, v := range s.cache {
			if oldest == "" || v.expires.Before(expiry) {
				oldest = k
				expiry = v.expires
			}
		}
		clear(s.cache[oldest].value)
		delete(s.cache, oldest)
	}
	// Concurrent requests may finish in a different order. Keep the earliest
	// surviving expiry rather than extending a version's existing cache lifetime.
	if old, ok := s.cache[key]; ok && s.now().Before(old.expires) {
		return old.expires
	}
	if old, ok := s.cache[key]; ok {
		clear(old.value)
	}
	e.value = append([]byte(nil), e.value...)
	s.cache[key] = e
	return e.expires
}
func (s *Service) Resolve(ctx context.Context, namespace, ksa string, r Request) (Response, error) {
	var result Response
	if s.Repo == nil || s.Secrets == nil || !r.valid() {
		return result, ErrUnavailable
	}
	binding, e := s.Repo.Resolve(ctx, namespace, ksa, r)
	if e != nil || !binding.valid() {
		return result, s.unavailable("database_or_binding")
	}
	key := binding.Resource + "/versions/" + binding.Version
	cached, ok := s.cached(key)
	if !ok {
		started := s.now()
		fetchCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
		value, err := s.Secrets.Access(fetchCtx, key)
		cancel()
		if err != nil {
			clear(value)
			return result, s.unavailable("secret_manager")
		}
		if len(value) > MaxHeaderBytes || !safeHeader(value) {
			clear(value)
			return result, s.unavailable("invalid_secret_header")
		}
		cached = entry{value, started.Add(CacheLifetime)}
		cached.expires = s.put(key, cached)
	}
	defer clear(cached.value)
	// Rotation/disable, attempt claim or identity revocation during a slow fetch
	// must not return a secret authorized by only the earlier database snapshot.
	current, e := s.Repo.Resolve(ctx, namespace, ksa, r)
	if e != nil || current != binding || !s.now().Before(cached.expires) || ctx.Err() != nil {
		return result, s.unavailable("revalidation")
	}
	value := string(cached.value)
	if binding.Format == "bearer" {
		value = "Bearer " + value
	}
	if len(binding.HeaderName)+len(value)+4 > MaxHeaderBytes {
		return result, s.unavailable("invalid_secret_header")
	}
	result = Response{binding.Version, binding.HeaderName, value, cached.expires.UTC()}
	if s.Observe != nil {
		s.Observe(Metadata{binding.Resource, binding.Version})
	}
	return result, nil
}

// PurgeExpired removes expired cache entries; call periodically even when idle.
// Go does not guarantee erasure of prior heap copies or response strings.
func (s *Service) PurgeExpired() {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.now()
	for key, e := range s.cache {
		if !now.Before(e.expires) {
			clear(e.value)
			delete(s.cache, key)
		}
	}
}
