package client

import (
	"crypto/tls"
	"net"
	"net/http"
	"os"
)

type Doer interface {
	Do(req *http.Request) (*http.Response, error)
}

// Fetch calls through an interface; VTA resolves it to *http.Client.
func Fetch(url string) error {
	var d Doer = &http.Client{}
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return err
	}
	_, err = d.Do(req)
	return err
}

func Dial(addr string) error {
	c, err := tls.Dial("tcp", addr, &tls.Config{})
	if err != nil {
		return err
	}
	return c.Close()
}

func Resolve(host string) ([]string, error) { return net.LookupHost(host) }

func ReadConfig(p string) ([]byte, error) { return os.ReadFile(p) }

func Getenv() string { return os.Getenv("HOME") }
