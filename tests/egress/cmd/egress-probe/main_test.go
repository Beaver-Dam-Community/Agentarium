package main

import (
	"context"
	"encoding/json"
	"net"
	"testing"
	"time"

	"golang.org/x/net/dns/dnsmessage"
)

func TestTCPReachableAndRefused(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	v := target{Name: "tcp", Network: "tcp", Address: ln.Addr().String(), Expect: "reachable"}
	if r := probe(context.Background(), v, time.Second); !r.ExpectationMet {
		t.Fatalf("%+v", r)
	}
	ln.Close()
	v.Expect = "timeout"
	if r := probe(context.Background(), v, time.Second); r.Outcome != "refused" || r.ExpectationMet {
		t.Fatalf("refusal must not count as isolation: %+v", r)
	}
}

func TestDNSRequiresResponseNotUDPDial(t *testing.T) {
	c, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	v := target{Name: "dns", Network: "dns-udp", Address: c.LocalAddr().String(), Query: "fixture.invalid.", Expect: "timeout"}
	if r := probe(context.Background(), v, 25*time.Millisecond); !r.ExpectationMet {
		t.Fatalf("UDP dial alone must not pass: %+v", r)
	}
	go func() {
		buf := make([]byte, 1024)
		for {
			n, peer, err := c.ReadFrom(buf)
			if err != nil {
				return
			}
			var q dnsmessage.Message
			if q.Unpack(buf[:n]) != nil || len(q.Questions) != 1 {
				continue
			}
			q.Header.Response = true
			q.Answers = []dnsmessage.Resource{{Header: dnsmessage.ResourceHeader{Name: q.Questions[0].Name, Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET, TTL: 1}, Body: &dnsmessage.AResource{A: [4]byte{192, 0, 2, 1}}}}
			response, _ := q.Pack()
			c.WriteTo(response, peer)
		}
	}()
	v.Expect = "reachable"
	if r := probe(context.Background(), v, time.Second); !r.ExpectationMet {
		t.Fatalf("DNS answer should pass: %+v", r)
	}
}

func TestCancellationIsNotDenial(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	r := probe(ctx, target{Network: "tcp", Address: "127.0.0.1:1", Expect: "timeout"}, time.Second)
	if r.Outcome != "cancelled" || r.ExpectationMet {
		t.Fatalf("%+v", r)
	}
}

func TestConfigurationRejectsAmbientDNSAndAmbiguity(t *testing.T) {
	valid := target{Name: "a", Network: "tcp", Address: "127.0.0.1:8443", Expect: "reachable"}
	for name, change := range map[string]func(*target){
		"hostname":            func(v *target) { v.Address = "metadata.google.internal:80" },
		"zero port":           func(v *target) { v.Address = "127.0.0.1:0" },
		"relative DNS":        func(v *target) { v.Network = "dns-udp"; v.Query = "kubernetes.default" },
		"unknown mode":        func(v *target) { v.Network = "udp" },
		"unknown expectation": func(v *target) { v.Expect = "deny" },
	} {
		t.Run(name, func(t *testing.T) {
			v := valid
			change(&v)
			b, _ := json.Marshal([]target{v})
			if _, err := parse(string(b)); err == nil {
				t.Fatal("accepted invalid configuration")
			}
		})
	}
	b, _ := json.Marshal([]target{valid})
	if _, err := parse(string(b)); err != nil {
		t.Fatal(err)
	}
	for _, raw := range []string{"[]", string(b) + " {}", `[{"name":"a","extra":true}]`} {
		if _, err := parse(raw); err == nil {
			t.Fatalf("accepted %s", raw)
		}
	}
}
