package workbuddy

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"

	"github.com/router-for-me/CLIProxyAPI/v8/internal/httpwire"
	"github.com/router-for-me/CLIProxyAPI/v8/sdk/proxyutil"
	"golang.org/x/net/proxy"
)

// Transports owns private HTTP/1.1 pools. Nothing is shared with other providers,
// accounts, products, credentials, endpoints or proxy routes.
type Transports struct {
	mu      sync.Mutex
	entries map[string]*transportEntry
	serial  uint64
	limit   int
	tls     *tls.Config
}

type transportEntry struct {
	transport *http.Transport
	used      uint64
}

func NewTransports(limit int, tlsConfig *tls.Config) *Transports {
	if limit < 1 {
		limit = 256
	}
	var privateTLS *tls.Config
	if tlsConfig != nil {
		privateTLS = tlsConfig.Clone()
	}
	return &Transports{entries: make(map[string]*transportEntry), limit: limit, tls: privateTLS}
}

// Client requires an already resolved proxy setting; empty means direct.
// It does not inherit ambient proxy variables or follow credential-bearing
// redirects. Authentication acquisition may add a deadline to its own context.
func (p *Transports) Client(c Credential, base, proxyURL string, order []string) (*http.Client, error) {
	if err := validateBaseURL(base); err != nil {
		return nil, err
	}
	u, errURL := url.Parse(base)
	if errURL != nil {
		return nil, fmt.Errorf("workbuddy: invalid upstream URL")
	}
	sum := sha256.Sum256([]byte(IdentityKey(c, proxyURL) + "\x00" + c.AccessToken + "\x00" +
		u.Scheme + "://" + u.Host + "\x00" + strings.Join(order, "\x00")))
	key := hex.EncodeToString(sum[:])
	p.mu.Lock()
	defer p.mu.Unlock()
	p.serial++
	if entry := p.entries[key]; entry != nil {
		entry.used = p.serial
		return transportClient(entry.transport), nil
	}
	transport, errTransport := p.newTransport(proxyURL, order)
	if errTransport != nil {
		return nil, errTransport
	}
	if len(p.entries) >= p.limit {
		var oldest string
		var oldestSerial uint64
		for candidate, entry := range p.entries {
			if oldest == "" || entry.used < oldestSerial {
				oldest, oldestSerial = candidate, entry.used
			}
		}
		p.entries[oldest].transport.CloseIdleConnections()
		delete(p.entries, oldest)
	}
	p.entries[key] = &transportEntry{transport: transport, used: p.serial}
	return transportClient(transport), nil
}

func transportClient(transport *http.Transport) *http.Client {
	return &http.Client{
		Transport: transport,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
}

func (p *Transports) newTransport(proxyURL string, order []string) (*http.Transport, error) {
	dialer, _, errDialer := proxyutil.BuildDialer(proxyURL)
	if errDialer != nil {
		return nil, fmt.Errorf("workbuddy: invalid proxy configuration")
	}
	if dialer == nil {
		dialer = proxy.Direct
	}
	contextDialer, ok := dialer.(proxy.ContextDialer)
	if !ok {
		return nil, fmt.Errorf("workbuddy: proxy must support context cancellation")
	}
	wireOrder := append([]string(nil), order...)
	ordered := func(conn net.Conn) net.Conn {
		return httpwire.NewOrderedRequestConn(conn, func(string, string) []string { return wireOrder })
	}
	transport := &http.Transport{
		MaxIdleConns:        2,
		MaxIdleConnsPerHost: 2,
		DisableCompression:  true,
		// Explicitly retain zero deadlines for established streams.
		TLSNextProto: map[string]func(string, *tls.Conn) http.RoundTripper{},
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			conn, errDial := contextDialer.DialContext(ctx, network, addr)
			if errDial != nil {
				return nil, errDial
			}
			return ordered(conn), nil
		},
		DialTLSContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			conn, errDial := contextDialer.DialContext(ctx, network, addr)
			if errDial != nil {
				return nil, errDial
			}
			host, _, errHost := net.SplitHostPort(addr)
			if errHost != nil {
				if errClose := conn.Close(); errClose != nil {
					return nil, fmt.Errorf("workbuddy: invalid TLS address: %w; close: %v", errHost, errClose)
				}
				return nil, errHost
			}
			tlsConfig := &tls.Config{MinVersion: tls.VersionTLS12}
			if p.tls != nil {
				tlsConfig = p.tls.Clone()
			}
			tlsConfig.ServerName = host
			tlsConfig.NextProtos = []string{"http/1.1"}
			tlsConn := tls.Client(conn, tlsConfig)
			if errHandshake := tlsConn.HandshakeContext(ctx); errHandshake != nil {
				if errClose := conn.Close(); errClose != nil {
					return nil, fmt.Errorf("workbuddy: TLS handshake: %w; close: %v", errHandshake, errClose)
				}
				return nil, errHandshake
			}
			return ordered(tlsConn), nil
		},
	}
	return transport, nil
}

func (p *Transports) CloseIdleConnections() {
	p.mu.Lock()
	defer p.mu.Unlock()
	for _, entry := range p.entries {
		entry.transport.CloseIdleConnections()
	}
	clear(p.entries)
}
