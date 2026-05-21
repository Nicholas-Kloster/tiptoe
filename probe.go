package main

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"time"
)

// probePort runs one quiet active probe of one port. It opens a single TCP
// connection — the connect time is the RTT signal the pacer reads — and then,
// if the port is open, runs a short identification step biased toward AI/LLM
// services. Every request is read-only; tiptoe never sends a credential.
func probePort(ip, hostname string, port int, timeout time.Duration) Probe {
	p := Probe{Port: port, Provenance: ProvActive}

	rtt, open, reset := dialRTT(ip, port, timeout)
	p.RTT = rtt
	p.RTTms = rtt.Seconds() * 1000
	if !open {
		if reset {
			p.State = StateReset
			p.Evidence = "TCP RST — the host actively refused the connection"
		} else {
			p.State = StateSilent
			p.Evidence = "no TCP handshake — the SYN was dropped (filtered)"
		}
		return p
	}
	p.TCPOpen = true
	identify(&p, ip, hostname, port, timeout)
	return p
}

// dialRTT opens one TCP connection and times it. The connect duration is the
// cleanest available RTT sample: it is server-side-processing-free, so it is a
// faithful signal of network and middlebox latency for the pacer.
func dialRTT(ip string, port int, timeout time.Duration) (time.Duration, bool, bool) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	d := net.Dialer{}
	start := time.Now()
	conn, err := d.DialContext(ctx, "tcp", net.JoinHostPort(ip, fmt.Sprint(port)))
	rtt := time.Since(start)
	if err != nil {
		// A dropped SYN (filtered) surfaces as a timeout; a RST as a refusal.
		// The typed net.Error check also catches a context-deadline timeout.
		var nErr net.Error
		if errors.As(err, &nErr) && nErr.Timeout() {
			return rtt, false, false
		}
		return rtt, false, strings.Contains(err.Error(), "refused")
	}
	_ = conn.Close()
	return rtt, true, false
}

// identify runs the AI/LLM-focused fingerprint ladder against an open port and
// fills in the Probe's service, state, severity and evidence. It makes at most
// a handful of requests, all to one port, all read-only.
func identify(p *Probe, ip, hostname string, port int, timeout time.Duration) {
	client := newHTTPClient(timeout)
	host := ip
	if hostname != "" && net.ParseIP(hostname) == nil {
		host = hostname // prefer the name — virtual-hosted services need it
	}

	for _, scheme := range []string{"http", "https"} {
		base := fmt.Sprintf("%s://%s:%d", scheme, host, port)
		st, hdr, body, ok := httpGet(client, base+"/")
		if !ok {
			continue
		}

		// Ollama — answers "/" with a plain-text liveness string, no auth.
		if strings.Contains(body, "Ollama is running") {
			_, _, tags, _ := httpGet(client, base+"/api/tags")
			n := strings.Count(tags, `"name"`)
			p.Service, p.State, p.Severity = "Ollama", StateUnauth, "HIGH"
			p.Evidence = fmt.Sprintf("Ollama answered /api/tags unauthenticated "+
				"(%d model entries; no auth — Ollama ships none)", n)
			return
		}

		// JupyterHub — multi-user. /hub/api carries the version; /hub/api/users
		// is admin-scoped and is the auth-state marker.
		if strings.Contains(body, "JupyterHub") || strings.Contains(hdr, "/hub/") ||
			strings.Contains(body, "/hub/login") {
			_, _, hubAPI, _ := httpGet(client, base+"/hub/api")
			ver := jsonField(hubAPI, "version")
			us, _, _, _ := httpGet(client, base+"/hub/api/users")
			if us == 200 {
				p.Service, p.State, p.Severity = "JupyterHub", StateUnauth, "HIGH"
				p.Evidence = fmt.Sprintf("JupyterHub %s — /hub/api/users answered "+
					"200 with no token (admin API readable)", ver)
			} else {
				p.Service, p.State, p.Severity = "JupyterHub", StateAuth, "LOW"
				p.Evidence = fmt.Sprintf("JupyterHub %s confirmed; /hub/api/users "+
					"-> %d (authentication enforced)", ver, us)
			}
			return
		}

		// Jupyter Server / Notebook — single-user. /api carries the version.
		if apiSt, _, apiBody, _ := httpGet(client, base+"/api"); apiSt == 200 &&
			strings.Contains(apiBody, `"version"`) {
			ver := jsonField(apiBody, "version")
			cs, _, _, _ := httpGet(client, base+"/api/contents")
			if cs == 200 {
				p.Service, p.State, p.Severity = "Jupyter Server", StateUnauth, "HIGH"
				p.Evidence = fmt.Sprintf("Jupyter Server %s — /api/contents "+
					"answered 200 with no token (notebook tree readable)", ver)
			} else {
				p.Service, p.State, p.Severity = "Jupyter Server", StateAuth, "LOW"
				p.Evidence = fmt.Sprintf("Jupyter Server %s confirmed; "+
					"/api/contents -> %d (token required)", ver, cs)
			}
			return
		}

		// vLLM / any OpenAI-compatible model server — /v1/models lists models.
		if mSt, _, mBody, _ := httpGet(client, base+"/v1/models"); mSt == 200 &&
			strings.Contains(mBody, `"data"`) {
			n := strings.Count(mBody, `"id"`)
			p.Service, p.State, p.Severity = "OpenAI-compatible model server",
				StateUnauth, "HIGH"
			p.Evidence = fmt.Sprintf("/v1/models answered 200 unauthenticated "+
				"(%d model(s) listed)", n)
			return
		}

		// generic HTTP — name it from the Server header or the page title.
		server := headerValue(hdr, "Server")
		title := pageTitle(body)
		desc := server
		if desc == "" {
			desc = title
		}
		if desc == "" {
			desc = fmt.Sprintf("HTTP %d", st)
		}
		p.Service, p.State, p.Severity = "web service", StateOther, "INFO"
		p.Evidence = fmt.Sprintf("HTTP %d, %s — not a recognized AI/LLM service", st, desc)
		return
	}

	// not HTTP — try a plain banner read
	if b := bannerGrab(ip, port, timeout); b != "" {
		p.Service, p.State, p.Severity = "unidentified", StateOpen, "INFO"
		p.Evidence = "banner: " + b
		return
	}
	p.Service, p.State, p.Severity = "unidentified", StateOpen, "INFO"
	p.Evidence = "TCP open; no HTTP response and no banner — service not identified"
}

func newHTTPClient(timeout time.Duration) *http.Client {
	return &http.Client{
		Timeout: timeout,
		// keep-alives ON: the 2-3 requests to one port reuse one connection,
		// which is quieter than a fresh connection per request.
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
		// do not follow redirects — the redirect target is itself a signal
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
}

// httpGet performs one GET and returns status, a flattened header string, a
// capped body, and whether the request reached a server at all.
func httpGet(client *http.Client, url string) (int, string, string, bool) {
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return 0, "", "", false
	}
	req.Header.Set("User-Agent", "tiptoe/"+version)
	resp, err := client.Do(req)
	if err != nil {
		return 0, "", "", false
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 16<<10))
	var h strings.Builder
	for k, v := range resp.Header {
		fmt.Fprintf(&h, "%s: %s\n", k, strings.Join(v, ","))
	}
	return resp.StatusCode, h.String(), string(body), true
}

// bannerGrab reads whatever a non-HTTP service volunteers on connect.
func bannerGrab(ip string, port int, timeout time.Duration) string {
	conn, err := net.DialTimeout("tcp", net.JoinHostPort(ip, fmt.Sprint(port)), timeout)
	if err != nil {
		return ""
	}
	defer conn.Close()
	_ = conn.SetReadDeadline(time.Now().Add(timeout))
	buf := make([]byte, 256)
	n, _ := conn.Read(buf)
	return strings.TrimSpace(string(buf[:n]))
}

func headerValue(flat, key string) string {
	for _, line := range strings.Split(flat, "\n") {
		if k, v, ok := strings.Cut(line, ": "); ok &&
			strings.EqualFold(strings.TrimSpace(k), key) {
			return strings.TrimSpace(v)
		}
	}
	return ""
}

func pageTitle(body string) string {
	low := strings.ToLower(body)
	i := strings.Index(low, "<title>")
	if i < 0 {
		return ""
	}
	j := strings.Index(low[i:], "</title>")
	if j < 0 {
		return ""
	}
	t := strings.TrimSpace(body[i+7 : i+j])
	if len(t) > 60 {
		t = t[:60]
	}
	return t
}

// jsonField pulls a top-level "key":"value" string out of a small JSON body
// without a full parse — enough for a version string.
func jsonField(body, key string) string {
	needle := `"` + key + `"`
	i := strings.Index(body, needle)
	if i < 0 {
		return "?"
	}
	rest := body[i+len(needle):]
	q1 := strings.Index(rest, `"`)
	if q1 < 0 {
		return "?"
	}
	q2 := strings.Index(rest[q1+1:], `"`)
	if q2 < 0 {
		return "?"
	}
	return rest[q1+1 : q1+1+q2]
}
