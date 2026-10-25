// Package offense implements authorized, bounded validation of the php2shell
// engine bugs. It deliberately stops at exploitability signals: no code
// execution, webshells, reverse shells, credential theft or persistence.
package offense

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/url"
	"os"
	"path"
	"strings"
	"time"
)

// Scope is the operator-supplied authorization record. It mirrors the written
// authorization a tester normally keeps on file: case, owner, expiry and the
// exact endpoints in scope.
type Scope struct {
	CaseID                string    `json:"case_id"`
	Operator              string    `json:"operator"`
	Expires               time.Time `json:"expires"`
	Targets               []string  `json:"targets"`
	AllowPublic           bool      `json:"allow_public"`
	AcknowledgeDisruption bool      `json:"acknowledge_disruption"`
}

// LoadScope reads and validates a JSON authorization file.
func LoadScope(file string) (*Scope, error) {
	if strings.TrimSpace(file) == "" {
		return nil, errors.New("an authorization scope file is required (--authorize)")
	}
	data, err := os.ReadFile(file)
	if err != nil {
		return nil, fmt.Errorf("read authorization scope: %w", err)
	}
	dec := json.NewDecoder(strings.NewReader(string(data)))
	dec.DisallowUnknownFields()
	var s Scope
	if err := dec.Decode(&s); err != nil {
		return nil, fmt.Errorf("parse authorization scope: %w", err)
	}
	if err := s.Validate(time.Now().UTC()); err != nil {
		return nil, err
	}
	return &s, nil
}

// Validate rejects incomplete, expired or malformed authorizations.
func (s *Scope) Validate(now time.Time) error {
	if s == nil {
		return errors.New("authorization scope is missing")
	}
	if strings.TrimSpace(s.CaseID) == "" {
		return errors.New("authorization scope needs a case_id")
	}
	if strings.TrimSpace(s.Operator) == "" {
		return errors.New("authorization scope needs an operator")
	}
	if strings.ContainsFunc(s.CaseID, isControl) || strings.ContainsFunc(s.Operator, isControl) {
		return errors.New("case_id and operator must not contain control characters")
	}
	if s.Expires.IsZero() {
		return errors.New("authorization scope needs an expires timestamp")
	}
	if !s.Expires.After(now) {
		return fmt.Errorf("authorization scope expired at %s", s.Expires.UTC().Format(time.RFC3339))
	}
	if len(s.Targets) == 0 {
		return errors.New("authorization scope lists no targets")
	}
	for _, raw := range s.Targets {
		u, err := url.Parse(strings.TrimSpace(raw))
		if err != nil || u.Host == "" {
			return fmt.Errorf("invalid scope target %q", raw)
		}
		if u.Scheme != "http" && u.Scheme != "https" {
			return fmt.Errorf("scope target %q must use http or https", raw)
		}
	}
	return nil
}

// Allows reports whether rawURL is covered by the scope. A base URL authorizes
// its own path and everything below it; host, port and scheme must match.
func (s *Scope) Allows(rawURL string) bool {
	if s == nil {
		return false
	}
	u, err := url.Parse(strings.TrimSpace(rawURL))
	if err != nil || u.Host == "" {
		return false
	}
	for _, raw := range s.Targets {
		base, err := url.Parse(strings.TrimSpace(raw))
		if err != nil {
			continue
		}
		if !strings.EqualFold(base.Scheme, u.Scheme) || !strings.EqualFold(base.Host, u.Host) {
			continue
		}
		bp := path.Clean("/" + base.Path)
		up := path.Clean("/" + u.Path)
		if bp == "/" || up == bp || strings.HasPrefix(up, bp+"/") {
			return true
		}
	}
	return false
}

// MaxTargets bounds one validation run so a scope mistake cannot fan out into
// a large number of active requests.
const MaxTargets = 16

// AuthorizeTargets performs the pre-flight checks that must pass before any
// request is sent: scope membership, scheme, and public-address policy.
func AuthorizeTargets(ctx context.Context, scope *Scope, targets []string, allowPublic bool) error {
	if err := scope.Validate(time.Now().UTC()); err != nil {
		return err
	}
	if len(targets) == 0 {
		return errors.New("at least one --target is required")
	}
	if len(targets) > MaxTargets {
		return fmt.Errorf("too many targets: %d (maximum %d)", len(targets), MaxTargets)
	}
	for _, raw := range targets {
		u, err := url.Parse(strings.TrimSpace(raw))
		if err != nil || u.Host == "" {
			return fmt.Errorf("invalid target %q", raw)
		}
		if u.Scheme != "http" && u.Scheme != "https" {
			return fmt.Errorf("target %q must use http or https", raw)
		}
		if !scope.Allows(raw) {
			return fmt.Errorf("%s is not listed in authorization case %s", raw, scope.CaseID)
		}
		public, err := HostIsPublic(ctx, u.Host)
		if err != nil {
			return fmt.Errorf("classify target %s: %w", raw, err)
		}
		if public && (!scope.AllowPublic || !allowPublic) {
			return fmt.Errorf("%s resolves to a public address; the scope must set allow_public and the run must pass --allow-public", raw)
		}
	}
	return nil
}

// HostIsPublic resolves a host:port and reports whether any address is public.
func HostIsPublic(ctx context.Context, hostport string) (bool, error) {
	host := hostport
	if h, _, err := net.SplitHostPort(hostport); err == nil {
		host = h
	}
	host = strings.Trim(host, "[]")
	if host == "" {
		return false, errors.New("empty host")
	}
	if ip := net.ParseIP(host); ip != nil {
		return !privateIP(ip), nil
	}
	if strings.EqualFold(host, "localhost") {
		return false, nil
	}
	lookupCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	addrs, err := net.DefaultResolver.LookupIPAddr(lookupCtx, host)
	if err != nil {
		return false, err
	}
	if len(addrs) == 0 {
		return false, errors.New("no addresses returned")
	}
	for _, addr := range addrs {
		if !privateIP(addr.IP) {
			return true, nil
		}
	}
	return false, nil
}

func privateIP(ip net.IP) bool {
	return ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() ||
		ip.IsLinkLocalMulticast() || ip.IsUnspecified()
}

func isControl(r rune) bool { return r < 32 || r == 0x7f }
