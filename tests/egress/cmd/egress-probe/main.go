// egress-probe records transport observations from an admitted test Pod. It
// never obtains credentials, changes policies, or interprets a timeout as proof
// that NetworkPolicy caused a failure. Configuration is environment-only so it
// can run under the existing agent-exec probe profile (which forbids args).
package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"
)

type target struct {
	Name    string `json:"name"`
	Network string `json:"network"` // tcp, dns-udp, dns-tcp
	Address string `json:"address"` // literal IP:port; never use ambient DNS
	Query   string `json:"query,omitempty"`
	Expect  string `json:"expect"` // reachable or timeout
}

type observation struct {
	Target         target    `json:"target"`
	StartedAt      time.Time `json:"started_at"`
	DurationMS     int64     `json:"duration_ms"`
	Outcome        string    `json:"outcome"`
	Error          string    `json:"error,omitempty"`
	ExpectationMet bool      `json:"expectation_met"`
}

func parse(raw string) ([]target, error) {
	var targets []target
	d := json.NewDecoder(strings.NewReader(raw))
	d.DisallowUnknownFields()
	if err := d.Decode(&targets); err != nil {
		return nil, err
	}
	var extra any
	if err := d.Decode(&extra); err != io.EOF {
		return nil, errors.New("expected one JSON array")
	}
	if len(targets) < 1 || len(targets) > 16 {
		return nil, errors.New("expected 1..16 targets")
	}
	names := map[string]bool{}
	for _, t := range targets {
		a, err := netip.ParseAddrPort(t.Address)
		if err != nil || a.Port() == 0 || a.Addr().IsUnspecified() || a.Addr().IsMulticast() || a.Addr().Zone() != "" {
			return nil, fmt.Errorf("%s: expected literal unicast IP:port", t.Name)
		}
		if t.Name == "" || names[t.Name] {
			return nil, errors.New("target names must be nonempty and unique")
		}
		names[t.Name] = true
		if t.Expect != "reachable" && t.Expect != "timeout" {
			return nil, errors.New("expect must be reachable or timeout")
		}
		switch t.Network {
		case "tcp":
			if t.Query != "" {
				return nil, errors.New("tcp target must not have a DNS query")
			}
		case "dns-udp", "dns-tcp":
			if t.Query == "" || len(t.Query) > 253 || !strings.HasSuffix(t.Query, ".") {
				return nil, errors.New("DNS query must be an absolute name ending in a dot")
			}
		default:
			return nil, errors.New("unsupported network")
		}
	}
	return targets, nil
}

func probe(parent context.Context, t target, timeout time.Duration) observation {
	r := observation{Target: t, StartedAt: time.Now().UTC()}
	ctx, cancel := context.WithTimeout(parent, timeout)
	defer cancel()
	dial := &net.Dialer{}
	var err error
	if t.Network == "tcp" {
		var conn net.Conn
		conn, err = dial.DialContext(ctx, "tcp", t.Address)
		if conn != nil {
			conn.Close()
		}
	} else {
		network := strings.TrimPrefix(t.Network, "dns-")
		resolver := net.Resolver{PreferGo: true, StrictErrors: true, Dial: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return dial.DialContext(ctx, network, t.Address)
		}}
		var addresses []net.IP
		addresses, err = resolver.LookupIP(ctx, "ip4", t.Query)
		if err == nil && len(addresses) == 0 {
			err = errors.New("DNS returned no IPv4 answer")
		}
	}
	r.DurationMS = time.Since(r.StartedAt).Milliseconds()
	r.Outcome = "reachable"
	if err != nil {
		r.Error = err.Error()
		var ne net.Error
		switch {
		case errors.Is(err, context.Canceled):
			r.Outcome = "cancelled"
		case errors.Is(err, syscall.ECONNREFUSED):
			r.Outcome = "refused"
		case errors.As(err, &ne) && ne.Timeout():
			r.Outcome = "timeout"
		default:
			r.Outcome = "error"
		}
	}
	r.ExpectationMet = r.Outcome == t.Expect
	return r
}

func run(ctx context.Context, out io.Writer, raw string) error {
	targets, err := parse(raw)
	if err != nil {
		return err
	}
	enc := json.NewEncoder(out)
	matched := true
	for _, t := range targets {
		if err := ctx.Err(); err != nil {
			return err
		}
		r := probe(ctx, t, 3*time.Second)
		if err := enc.Encode(r); err != nil {
			return err
		}
		matched = matched && r.ExpectationMet
	}
	if !matched {
		return errors.New("one or more transport observations differ from expectations")
	}
	return nil
}

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	// The fixed listener is only a TCP positive control; it handles no HTTP,
	// tokens, or application requests and logs no received content.
	if os.Getenv("EGRESS_LISTEN") == "1" {
		ln, err := net.Listen("tcp", ":8443")
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		go func() { <-ctx.Done(); ln.Close() }()
		fmt.Println(`{"listener":"ready","port":8443}`)
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			conn.Close()
		}
	}
	if err := run(ctx, os.Stdout, os.Getenv("EGRESS_TARGETS")); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
