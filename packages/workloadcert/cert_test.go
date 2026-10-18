package workloadcert_test

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/Beaver-Dam-Community/Agentarium/packages/workloadcert"
	"github.com/Beaver-Dam-Community/Agentarium/packages/workloadcert/workloadcerttest"
)

func TestBootstrapAndIdentityValidation(t *testing.T) {
	serviceSAN := "spiffe://agentarium.internal/ns/agent-observe/sa/audit-writer"
	id := workloadcerttest.Start(t, serviceSAN)
	m := &workloadcert.Manager{URL: id.URL, TokenFile: id.TokenFile, CAFile: id.CAFile, SAN: serviceSAN}
	if err := m.Refresh(context.Background()); err != nil {
		t.Fatal(err)
	}
	first, err := m.Certificate()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := m.ServerTLS(); err != nil {
		t.Fatal(err)
	}
	id.Wrong.Store(true)
	if err := m.Refresh(context.Background()); err == nil {
		t.Fatal("wrong service SAN accepted")
	}
	after, _ := m.Certificate()
	if first != after {
		t.Fatal("failed rotation discarded valid identity")
	}
	if err := os.WriteFile(id.CAFile, []byte("invalid"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := m.Refresh(context.Background()); err == nil {
		t.Fatal("untrusted issuer accepted")
	}
	if _, err := m.ServerTLS(); err == nil {
		t.Fatal("invalid roots accepted")
	}
}

func TestStartFailsClosed(t *testing.T) {
	serviceSAN := "spiffe://agentarium.internal/ns/agent-control/sa/coordinator"
	id := workloadcerttest.Start(t, serviceSAN)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	m := &workloadcert.Manager{URL: id.URL, TokenFile: id.TokenFile, CAFile: id.CAFile, SAN: serviceSAN}
	if err := m.Start(ctx, func() {}); err != nil {
		t.Fatal(err)
	}
	if c, err := m.GetCertificate(nil); err != nil || c.Leaf.URIs[0].String() != serviceSAN {
		t.Fatalf("GetCertificate = %v, %v", c, err)
	}
	if _, err := m.GetClientCertificate(nil); err != nil {
		t.Fatal(err)
	}

	for name, bad := range map[string]*workloadcert.Manager{
		"no token flag":  {URL: id.URL, CAFile: id.CAFile, SAN: serviceSAN},
		"missing token":  {URL: id.URL, TokenFile: filepath.Join(t.TempDir(), "absent"), CAFile: id.CAFile, SAN: serviceSAN},
		"no trust":       {URL: id.URL, TokenFile: id.TokenFile, SAN: serviceSAN},
		"other SAN":      {URL: id.URL, TokenFile: id.TokenFile, CAFile: id.CAFile, SAN: "spiffe://agentarium.internal/ns/agent-control/sa/policy-gateway"},
		"plain http URL": {URL: "http" + id.URL[len("https"):], TokenFile: id.TokenFile, CAFile: id.CAFile, SAN: serviceSAN},
	} {
		if err := bad.Start(ctx, func() {}); err == nil {
			t.Errorf("%s: Start succeeded", name)
		}
		if _, err := bad.Certificate(); err == nil {
			t.Errorf("%s: certificate available after failed start", name)
		}
	}
}
