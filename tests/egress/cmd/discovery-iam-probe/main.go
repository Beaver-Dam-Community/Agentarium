// discovery-iam-probe exercises TASK-06 bucket permissions using only the Pod's
// metadata credentials. It never falls back to a developer's ADC or a DB GSA.
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"html"
	"io"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strings"
	"time"
)

const payload = "Agentarium discovery IAM verification\n"

type config struct{ Bucket, RunID, Mode string }
type result struct {
	Operation string `json:"operation"`
	Status    int    `json:"status"`
	Passed    bool   `json:"passed"`
}
type probe struct {
	client                       *http.Client
	api, upload, metadata, token string
	cfg                          config
}

func readConfig() (config, error) {
	c := config{os.Getenv("IAM_BUCKET"), os.Getenv("IAM_RUN_ID"), os.Getenv("IAM_MODE")}
	if !regexp.MustCompile(`^[a-z0-9][a-z0-9_-]{1,61}[a-z0-9]$`).MatchString(c.Bucket) ||
		!regexp.MustCompile(`^[a-z0-9][a-z0-9-]{7,63}$`).MatchString(c.RunID) {
		return c, errors.New("invalid IAM_BUCKET or IAM_RUN_ID")
	}
	if c.Mode != "snapshot" && c.Mode != "reader" && c.Mode != "denied" {
		return c, errors.New("IAM_MODE must be snapshot, reader or denied")
	}
	return c, nil
}

func (p *probe) request(ctx context.Context, method, endpoint, body string, metadata bool) (int, []byte, error) {
	req, err := http.NewRequestWithContext(ctx, method, endpoint, strings.NewReader(body))
	if err != nil {
		return 0, nil, errors.New("request construction failed")
	}
	if metadata {
		req.Header.Set("Metadata-Flavor", "Google")
	} else {
		req.Header.Set("Authorization", "Bearer "+p.token)
		req.Header.Set("Content-Type", "text/plain")
	}
	resp, err := p.client.Do(req)
	if err != nil {
		return 0, nil, errors.New("transport failed")
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(io.LimitReader(resp.Body, 65537))
	if err != nil || len(b) > 65536 {
		return resp.StatusCode, nil, errors.New("invalid response size")
	}
	return resp.StatusCode, b, nil
}

// A timeout, 401, 404, 412 or retention-policy rejection is not IAM-denial proof.
func permissionDenied(status int, body []byte, permission string) bool {
	var e struct {
		Error struct {
			Message string
			Errors  []struct{ Reason string }
		}
	}
	if status != http.StatusForbidden {
		return false
	}
	if json.Unmarshal(body, &e) != nil {
		// GCS alt=media returns a plain-text, HTML-escaped access error rather
		// than the JSON API error envelope. Only accept its specific GET
		// permission-denied form, not arbitrary 403 text or an upstream page.
		message := html.UnescapeString(string(body))
		return permission == "storage.objects.get" &&
			strings.HasPrefix(message, "Caller does not have storage.objects.get access to the Google Cloud Storage object.") &&
			strings.Contains(message, "Permission 'storage.objects.get' denied on resource")
	}
	for _, detail := range e.Error.Errors {
		if detail.Reason == "forbidden" && strings.Contains(e.Error.Message, permission) {
			return true
		}
	}
	return false
}

func (p *probe) run(ctx context.Context) ([]result, error) {
	status, body, err := p.request(ctx, "GET", p.metadata, "", true)
	if err != nil || status != 200 {
		return nil, errors.New("metadata token unavailable")
	}
	var token struct {
		AccessToken string `json:"access_token"`
		TokenType   string `json:"token_type"`
	}
	if json.Unmarshal(body, &token) != nil || token.AccessToken == "" || !strings.EqualFold(token.TokenType, "Bearer") {
		return nil, errors.New("invalid metadata token response")
	}
	p.token = token.AccessToken
	defer func() { p.token = "" }()
	prefix := "snapshots/iam-check/" + p.cfg.RunID + "/"
	name := prefix + "fixture.txt"
	objURL := p.api + "/b/" + p.cfg.Bucket + "/o/" + url.PathEscape(name)
	create := func(name, content string, fresh bool) (int, []byte, error) {
		q := url.Values{"uploadType": {"media"}, "name": {name}}
		if fresh {
			q.Set("ifGenerationMatch", "0")
		}
		return p.request(ctx, "POST", p.upload+"/b/"+p.cfg.Bucket+"/o?"+q.Encode(), content, false)
	}
	var results []result
	record := func(op string, status int, ok bool, err error) {
		results = append(results, result{op, status, ok && err == nil})
	}
	createName := name
	if p.cfg.Mode != "snapshot" {
		createName = prefix + p.cfg.Mode + "-new.txt"
	}
	status, body, err = create(createName, payload, true)
	if p.cfg.Mode == "snapshot" {
		record("create", status, status == 200, err)
		if err != nil || status != 200 {
			return results, errors.New("fixture creation failed; use a fresh run ID")
		}
	} else {
		record("create", status, permissionDenied(status, body, "storage.objects.create"), err)
	}
	status, body, err = p.request(ctx, "GET", objURL+"?alt=media", "", false)
	if p.cfg.Mode == "denied" {
		record("get", status, permissionDenied(status, body, "storage.objects.get"), err)
	} else {
		record("get", status, status == 200 && bytes.Equal(body, []byte(payload)), err)
	}
	status, body, err = p.request(ctx, "GET", p.api+"/b/"+p.cfg.Bucket+"/o?"+url.Values{"prefix": {prefix}, "maxResults": {"20"}}.Encode(), "", false)
	if p.cfg.Mode == "denied" {
		record("list", status, permissionDenied(status, body, "storage.objects.list"), err)
	} else {
		var listing struct{ Items []struct{ Name string } }
		found := false
		if json.Unmarshal(body, &listing) == nil {
			for _, item := range listing.Items {
				found = found || item.Name == name
			}
		}
		record("list", status, status == 200 && found, err)
	}
	// Deliberately omit generation preconditions: 412 would test concurrency,
	// not whether the principal has the delete permission needed to overwrite.
	status, body, err = create(name, "unexpected overwrite\n", false)
	permission := "storage.objects.delete"
	if p.cfg.Mode != "snapshot" {
		permission = "storage.objects."
	}
	record("overwrite", status, permissionDenied(status, body, permission), err)
	status, body, err = p.request(ctx, "DELETE", objURL, "", false)
	record("delete", status, permissionDenied(status, body, "storage.objects.delete"), err)
	if p.cfg.Mode != "denied" {
		status, body, err = p.request(ctx, "GET", objURL+"?alt=media", "", false)
		record("preserved", status, status == 200 && bytes.Equal(body, []byte(payload)), err)
	}
	for _, r := range results {
		if !r.Passed {
			return results, errors.New("permission matrix failed")
		}
	}
	return results, nil
}

func main() {
	c, err := readConfig()
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.Proxy = nil
	p := probe{cfg: c, client: &http.Client{Transport: transport, Timeout: 15 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error { return errors.New("redirect refused") }},
		api: "https://storage.googleapis.com/storage/v1", upload: "https://storage.googleapis.com/upload/storage/v1",
		metadata: "http://169.254.169.254/computeMetadata/v1/instance/service-accounts/default/token"}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	results, err := p.run(ctx)
	_ = json.NewEncoder(os.Stdout).Encode(struct {
		Mode    string   `json:"mode"`
		Results []result `json:"results"`
	}{c.Mode, results})
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
