// opencode-tls-helper: loopback forwarder that makes OpenCode free-tier
// requests with a fixed, known-good TLS ClientHello (built with utls).
//
// Why: the free gate fingerprints the ClientHello. Node linked against
// OpenSSL < 3.5 (FreeBSD base ships 3.0) is refused even with the right
// cipher list: it appends TLS_EMPTY_RENEGOTIATION_INFO_SCSV and sends an older
// extension / signature-algorithm set. Go's crypto/tls is refused too (its
// extension set differs). This helper replays, field for field, the hello that
// Node 22 + OpenSSL 3.5 sends with the OpenCode cipher list, which the gate
// accepts (JA4 t13d1712h1_5b57614c22b0_8e6e362c5eac, measured 2026-11-21).
//
// Protocol (spoken by open-sse/services/opencodeTlsHelper.js):
//   - started with env OPENCODE_TLS_TOKEN (required, >= 32 chars)
//   - listens on 127.0.0.1:<random>, prints "PORT <n>" on stdout
//   - each request carries X-9r-Helper-Token, X-9r-Target (absolute https URL)
//     and optionally X-9r-Proxy (http, https or socks5 URL)
//   - exits when stdin closes, so it never outlives the parent process
//
// Security: requests without the token are refused (constant-time compare),
// so other users on a shared host cannot use the port as an open proxy. Only
// https targets are accepted, certificates are verified against the system
// roots, and nothing logs headers, bodies or URLs.
package main

import (
	"bufio"
	"context"
	"crypto/subtle"
	"encoding/base64"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"sync"
	"time"

	utls "github.com/refraction-networking/utls"
	"golang.org/x/net/proxy"
)

const (
	headerToken  = "X-9r-Helper-Token"
	headerTarget = "X-9r-Target"
	headerProxy  = "X-9r-Proxy"
	headerError  = "X-9r-Helper-Error"

	dialTimeout = 20 * time.Second
)

// Request headers never forwarded upstream: hop-by-hop (RFC 9110 7.6.1) and
// the helper's own control headers.
var dropRequestHeaders = []string{
	"Connection", "Keep-Alive", "Proxy-Connection", "Transfer-Encoding", "Te",
	"Trailer", "Upgrade", "Host", headerToken, headerTarget, headerProxy,
}

var dropResponseHeaders = []string{
	"Connection", "Keep-Alive", "Proxy-Connection", "Transfer-Encoding", "Te", "Trailer", "Upgrade",
}

// helloSpec reproduces Node 22 + OpenSSL 3.5's ClientHello for the OpenCode
// cipher list. Order and values come from tls.peet.ws (ja3 / peetprint):
//
//	ja3 771,4865-4866-4867-49195-49199-49196-49200-52393-52392-49161-49171-49162-49172-156-157-47-53,
//	    65281-0-11-10-35-16-22-23-13-43-45-51,4588-29-23-30-24-25-256-257,0-1-2
//
// A fresh spec per connection: utls mutates extension state during the handshake.
func helloSpec() *utls.ClientHelloSpec {
	return &utls.ClientHelloSpec{
		TLSVersMin: utls.VersionTLS12,
		TLSVersMax: utls.VersionTLS13,
		CipherSuites: []uint16{
			0x1301, 0x1302, 0x1303,
			0xc02b, 0xc02f, 0xc02c, 0xc030, 0xcca9, 0xcca8,
			0xc009, 0xc013, 0xc00a, 0xc014,
			0x009c, 0x009d, 0x002f, 0x0035,
		},
		CompressionMethods: []byte{0},
		Extensions: []utls.TLSExtension{
			&utls.RenegotiationInfoExtension{Renegotiation: utls.RenegotiateOnceAsClient},
			&utls.SNIExtension{},
			&utls.SupportedPointsExtension{SupportedPoints: []byte{0, 1, 2}},
			&utls.SupportedCurvesExtension{Curves: []utls.CurveID{
				utls.X25519MLKEM768, utls.X25519, utls.CurveP256, 30, utls.CurveP384, utls.CurveP521, 256, 257,
			}},
			&utls.SessionTicketExtension{},
			&utls.ALPNExtension{AlpnProtocols: []string{"http/1.1"}},
			&utls.GenericExtension{Id: 22}, // encrypt_then_mac (only affects CBC suites; TLS 1.3 is negotiated)
			&utls.ExtendedMasterSecretExtension{},
			&utls.SignatureAlgorithmsExtension{SupportedSignatureAlgorithms: []utls.SignatureScheme{
				0x0905, 0x0906, 0x0904, 0x0403, 0x0503, 0x0603, 0x0807, 0x0808, 0x081a, 0x081b, 0x081c,
				0x0809, 0x080a, 0x080b, 0x0804, 0x0805, 0x0806, 0x0401, 0x0501, 0x0601,
				0x0303, 0x0301, 0x0302, 0x0402, 0x0502, 0x0602,
			}},
			&utls.SupportedVersionsExtension{Versions: []uint16{utls.VersionTLS13, utls.VersionTLS12}},
			&utls.PSKKeyExchangeModesExtension{Modes: []uint8{utls.PskModeDHE}},
			&utls.KeyShareExtension{KeyShares: []utls.KeyShare{
				{Group: utls.X25519MLKEM768},
				{Group: utls.X25519},
			}},
		},
	}
}

// dialRaw opens the TCP stream to addr, directly or through the proxy.
func dialRaw(ctx context.Context, proxyURL *url.URL, addr string) (net.Conn, error) {
	d := &net.Dialer{Timeout: dialTimeout, KeepAlive: 30 * time.Second}
	if proxyURL == nil {
		return d.DialContext(ctx, "tcp", addr)
	}
	switch proxyURL.Scheme {
	case "socks5", "socks5h":
		pd, err := proxy.FromURL(proxyURL, d)
		if err != nil {
			return nil, err
		}
		if cd, ok := pd.(proxy.ContextDialer); ok {
			return cd.DialContext(ctx, "tcp", addr)
		}
		return pd.Dial("tcp", addr)
	case "http", "https":
		return dialConnect(ctx, d, proxyURL, addr)
	}
	return nil, fmt.Errorf("unsupported proxy scheme")
}

// dialConnect tunnels through an HTTP(S) proxy with CONNECT.
func dialConnect(ctx context.Context, d *net.Dialer, proxyURL *url.URL, addr string) (net.Conn, error) {
	proxyAddr := proxyURL.Host
	if proxyURL.Port() == "" {
		if proxyURL.Scheme == "https" {
			proxyAddr = net.JoinHostPort(proxyURL.Hostname(), "443")
		} else {
			proxyAddr = net.JoinHostPort(proxyURL.Hostname(), "80")
		}
	}
	conn, err := d.DialContext(ctx, "tcp", proxyAddr)
	if err != nil {
		return nil, err
	}
	if proxyURL.Scheme == "https" {
		tlsConn := utls.Client(conn, &utls.Config{ServerName: proxyURL.Hostname()})
		if err := tlsConn.HandshakeContext(ctx); err != nil {
			conn.Close()
			return nil, err
		}
		conn = tlsConn
	}
	req := &http.Request{
		Method: http.MethodConnect,
		URL:    &url.URL{Opaque: addr},
		Host:   addr,
		Header: http.Header{},
	}
	if u := proxyURL.User; u != nil {
		pw, _ := u.Password()
		req.Header.Set("Proxy-Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte(u.Username()+":"+pw)))
	}
	_ = conn.SetDeadline(time.Now().Add(dialTimeout))
	if err := req.Write(conn); err != nil {
		conn.Close()
		return nil, err
	}
	br := bufio.NewReader(conn)
	res, err := http.ReadResponse(br, req)
	if err != nil {
		conn.Close()
		return nil, err
	}
	res.Body.Close()
	if res.StatusCode != http.StatusOK {
		conn.Close()
		return nil, fmt.Errorf("proxy CONNECT refused: %s", res.Status)
	}
	if br.Buffered() > 0 {
		conn.Close()
		return nil, fmt.Errorf("proxy sent data before the TLS handshake")
	}
	_ = conn.SetDeadline(time.Time{})
	return conn, nil
}

func newTransport(proxyURL *url.URL) *http.Transport {
	return &http.Transport{
		DialTLSContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			raw, err := dialRaw(ctx, proxyURL, addr)
			if err != nil {
				return nil, err
			}
			host, _, _ := net.SplitHostPort(addr)
			conn := utls.UClient(raw, &utls.Config{ServerName: host}, utls.HelloCustom)
			if err := conn.ApplyPreset(helloSpec()); err != nil {
				raw.Close()
				return nil, err
			}
			hsCtx, cancel := context.WithTimeout(ctx, dialTimeout)
			defer cancel()
			if err := conn.HandshakeContext(hsCtx); err != nil {
				raw.Close()
				return nil, err
			}
			return conn, nil
		},
		ForceAttemptHTTP2:     false,
		MaxIdleConnsPerHost:   8,
		IdleConnTimeout:       60 * time.Second,
		ResponseHeaderTimeout: 180 * time.Second,
	}
}

type helper struct {
	token      []byte
	mu         sync.Mutex
	transports map[string]*http.Transport
}

func (h *helper) transport(rawProxy string) (*http.Transport, error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if t, ok := h.transports[rawProxy]; ok {
		return t, nil
	}
	var proxyURL *url.URL
	if rawProxy != "" {
		u, err := url.Parse(rawProxy)
		if err != nil || u.Host == "" {
			return nil, fmt.Errorf("invalid proxy URL")
		}
		switch u.Scheme {
		case "http", "https", "socks5", "socks5h":
		default:
			return nil, fmt.Errorf("unsupported proxy scheme")
		}
		proxyURL = u
	}
	if len(h.transports) >= 8 {
		for k, old := range h.transports {
			old.CloseIdleConnections()
			delete(h.transports, k)
			break
		}
	}
	t := newTransport(proxyURL)
	h.transports[rawProxy] = t
	return t, nil
}

func fail(w http.ResponseWriter, status int, msg string) {
	w.Header().Set(headerError, "1")
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(status)
	_, _ = io.WriteString(w, msg)
}

func (h *helper) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if subtle.ConstantTimeCompare([]byte(r.Header.Get(headerToken)), h.token) != 1 {
		fail(w, http.StatusForbidden, "forbidden")
		return
	}
	target, err := url.Parse(r.Header.Get(headerTarget))
	if err != nil || target.Scheme != "https" || target.Host == "" {
		fail(w, http.StatusBadRequest, "target must be an absolute https URL")
		return
	}
	t, err := h.transport(r.Header.Get(headerProxy))
	if err != nil {
		fail(w, http.StatusBadRequest, err.Error())
		return
	}

	out, err := http.NewRequestWithContext(r.Context(), r.Method, target.String(), r.Body)
	if err != nil {
		fail(w, http.StatusBadRequest, "bad request")
		return
	}
	out.Header = r.Header.Clone()
	for _, k := range dropRequestHeaders {
		out.Header.Del(k)
	}
	out.ContentLength = r.ContentLength

	res, err := t.RoundTrip(out)
	if err != nil {
		fail(w, http.StatusBadGateway, "upstream: "+err.Error())
		return
	}
	defer res.Body.Close()

	for k, vs := range res.Header {
		for _, v := range vs {
			w.Header().Add(k, v)
		}
	}
	for _, k := range dropResponseHeaders {
		w.Header().Del(k)
	}
	w.WriteHeader(res.StatusCode)

	// Stream: flush every chunk so SSE events reach the client immediately.
	flusher, _ := w.(http.Flusher)
	buf := make([]byte, 32*1024)
	for {
		n, readErr := res.Body.Read(buf)
		if n > 0 {
			if _, writeErr := w.Write(buf[:n]); writeErr != nil {
				return
			}
			if flusher != nil {
				flusher.Flush()
			}
		}
		if readErr != nil {
			return
		}
	}
}

func main() {
	token := os.Getenv("OPENCODE_TLS_TOKEN")
	if len(token) < 32 {
		fmt.Fprintln(os.Stderr, "opencode-tls-helper: OPENCODE_TLS_TOKEN missing or too short")
		os.Exit(2)
	}
	_ = os.Unsetenv("OPENCODE_TLS_TOKEN")

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		fmt.Fprintln(os.Stderr, "opencode-tls-helper: listen:", err)
		os.Exit(1)
	}
	fmt.Printf("PORT %d\n", ln.Addr().(*net.TCPAddr).Port)

	// Parent gone -> stdin EOF -> exit.
	go func() {
		_, _ = io.Copy(io.Discard, os.Stdin)
		os.Exit(0)
	}()

	srv := &http.Server{
		Handler:           &helper{token: []byte(token), transports: map[string]*http.Transport{}},
		ReadHeaderTimeout: 10 * time.Second,
	}
	if err := srv.Serve(ln); err != nil {
		fmt.Fprintln(os.Stderr, "opencode-tls-helper:", err)
		os.Exit(1)
	}
}
