package workbuddy

import (
	"bufio"
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
)

func TestTransportConnectionIsolationAndTLSVerification(t *testing.T) {
	seen := make(chan string, 8)
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen <- r.RemoteAddr
		fmt.Fprint(w, "ok")
	}))
	defer server.Close()
	roots := x509.NewCertPool()
	roots.AddCert(server.Certificate())
	pools := NewTransports(8, &tls.Config{RootCAs: roots})
	defer pools.CloseIdleConnections()
	credential := testCredential()
	request := func(c Credential, pools *Transports) error {
		client, errClient := pools.Client(c, server.URL, "", []string{"Host", "X-User-Id"})
		if errClient != nil {
			return errClient
		}
		resp, errDo := client.Get(server.URL)
		if errDo != nil {
			return errDo
		}
		_, errRead := io.Copy(io.Discard, resp.Body)
		if errClose := resp.Body.Close(); errClose != nil {
			return errClose
		}
		return errRead
	}
	for range 2 {
		if err := request(credential, pools); err != nil {
			t.Fatal(err)
		}
	}
	first, second := <-seen, <-seen
	if first != second {
		t.Fatal("same identity did not reuse its connection")
	}
	for _, change := range []func(*Credential){
		func(c *Credential) { c.UID = "other-user" },
		func(c *Credential) { c.Product = CLI },
		func(c *Credential) { c.AccessToken = "rotated-token" },
		func(c *Credential) { c.Realm = China },
	} {
		modified := credential
		change(&modified)
		if err := request(modified, pools); err != nil {
			t.Fatal(err)
		}
		if addr := <-seen; addr == first {
			t.Fatal("connection crossed credential or identity boundary")
		}
	}
	untrusted := NewTransports(8, nil)
	defer untrusted.CloseIdleConnections()
	if err := request(credential, untrusted); err == nil {
		t.Fatal("untrusted upstream certificate accepted")
	}
}

func TestTransportWireOrderAndCancellation(t *testing.T) {
	listener, errListen := net.Listen("tcp", "127.0.0.1:0")
	if errListen != nil {
		t.Fatal(errListen)
	}
	defer func() {
		if err := listener.Close(); err != nil {
			t.Error(err)
		}
	}()
	headers := make(chan []string, 1)
	closed := make(chan struct{})
	go func() {
		defer close(closed)
		conn, errAccept := listener.Accept()
		if errAccept != nil {
			t.Error(errAccept)
			return
		}
		defer func() {
			if err := conn.Close(); err != nil {
				t.Error(err)
			}
		}()
		reader := bufio.NewReader(conn)
		var lines []string
		for {
			line, errRead := reader.ReadString('\n')
			if errRead != nil {
				t.Error(errRead)
				return
			}
			if line == "\r\n" {
				break
			}
			lines = append(lines, strings.TrimSpace(line))
		}
		fmt.Fprint(conn, "HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nTransfer-Encoding: chunked\r\n\r\n")
		headers <- lines
		// No body and no deadline: request cancellation must close this stream.
		_, errRead := reader.ReadByte()
		if errRead == nil {
			t.Error("expected client disconnect")
		}
	}()
	pools := NewTransports(8, nil)
	defer pools.CloseIdleConnections()
	client, errClient := pools.Client(testCredential(), "http://"+listener.Addr().String(), "", []string{"Host", "x-stainless-lang", "X-User-Id", "User-Agent"})
	if errClient != nil {
		t.Fatal(errClient)
	}
	transport := client.Transport.(*http.Transport)
	if client.Timeout != 0 || transport.ResponseHeaderTimeout != 0 || transport.TLSHandshakeTimeout != 0 || transport.IdleConnTimeout != 0 {
		t.Fatal("transport installed a forbidden deadline")
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	req, errRequest := http.NewRequestWithContext(ctx, http.MethodGet, "http://"+listener.Addr().String(), nil)
	if errRequest != nil {
		t.Fatal(errRequest)
	}
	req.Header.Set("X-User-Id", "fixture")
	req.Header.Set("x-stainless-lang", "js")
	resp, errDo := client.Do(req)
	if errDo != nil {
		t.Fatal(errDo)
	}
	lines := <-headers
	if !strings.HasPrefix(lines[1], "Host:") || lines[2] != "x-stainless-lang: js" || lines[3] != "X-User-Id: fixture" {
		t.Fatalf("wrong wire casing/order: %v", lines)
	}
	cancel()
	if _, errRead := io.ReadAll(resp.Body); errRead == nil {
		t.Fatal("canceled stream succeeded")
	}
	if errClose := resp.Body.Close(); errClose != nil {
		t.Fatal(errClose)
	}
	<-closed
}

func TestHTTPConnectProxyDoesNotReceiveUpstreamCredentials(t *testing.T) {
	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer fixture-token" {
			t.Error("upstream authorization missing")
		}
		fmt.Fprint(w, "ok")
	}))
	defer upstream.Close()
	proxyServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodConnect || r.Header.Get("Authorization") != "" {
			t.Error("proxy received an application request or token")
		}
		target, errDial := net.Dial("tcp", r.Host)
		if errDial != nil {
			t.Error(errDial)
			w.WriteHeader(http.StatusBadGateway)
			return
		}
		conn, _, errHijack := w.(http.Hijacker).Hijack()
		if errHijack != nil {
			t.Error(errHijack)
			target.Close()
			return
		}
		fmt.Fprint(conn, "HTTP/1.1 200 Connection Established\r\n\r\n")
		var wg sync.WaitGroup
		wg.Go(func() { io.Copy(target, conn); target.Close() })
		io.Copy(conn, target)
		conn.Close()
		wg.Wait()
	}))
	defer proxyServer.Close()
	roots := x509.NewCertPool()
	roots.AddCert(upstream.Certificate())
	pools := NewTransports(8, &tls.Config{RootCAs: roots})
	defer pools.CloseIdleConnections()
	client, errClient := pools.Client(testCredential(), upstream.URL, proxyServer.URL, []string{"Host", "Authorization"})
	if errClient != nil {
		t.Fatal(errClient)
	}
	req, errRequest := http.NewRequest(http.MethodGet, upstream.URL, nil)
	if errRequest != nil {
		t.Fatal(errRequest)
	}
	req.Header.Set("Authorization", "Bearer fixture-token")
	resp, errDo := client.Do(req)
	if errDo != nil {
		t.Fatal(errDo)
	}
	if _, errRead := io.Copy(io.Discard, resp.Body); errRead != nil {
		t.Fatal(errRead)
	}
	if errClose := resp.Body.Close(); errClose != nil {
		t.Fatal(errClose)
	}
}
