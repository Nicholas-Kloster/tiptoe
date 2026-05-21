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

// llmSignature describes how to identify one AI/LLM platform. The probe layer
// is a declarative table of these rather than a hardcoded chain, which makes
// the false-positive resistance an engineered property — a match is claimed
// only when the platform's own API answers — and makes adding the rest of the
// LLM-infra stack a one-row change.
type llmSignature struct {
	platform    string // display name
	family      string // model-runtime / notebook / ui
	rootHint    string // lowercase substring in GET / body or headers (a soft signal)
	confirmPath string // an API path that proves identity
	confirmHint string // a substring a 200 confirm response must contain
	versionKey  string // JSON key holding the version, when the confirm response has one
	authPath    string // path whose HTTP status reveals the auth state (optional)
	noAuth      bool   // platform ships no auth, so a confirmed match is itself an exposure
}

// signatures is tiptoe's LLM-infrastructure knowledge, kept as data. Every row
// was checked against how the platform actually answers; an unverified
// platform is left out rather than guessed. Table order is match priority:
// specific platforms before the generic OpenAI-compatible catch-all.
var signatures = []llmSignature{
	{platform: "Ollama", family: "model-runtime", rootHint: "ollama is running",
		confirmPath: "/api/tags", confirmHint: `"models"`, noAuth: true},
	{platform: "JupyterHub", family: "notebook", rootHint: "/hub/",
		confirmPath: "/hub/api", confirmHint: `"version"`, versionKey: "version",
		authPath: "/hub/api/users"},
	{platform: "Open WebUI", family: "ui", rootHint: "open webui",
		confirmPath: "/api/config", confirmHint: `"name"`, versionKey: "version"},
	{platform: "Gradio", family: "ui", rootHint: "gradio",
		confirmPath: "/config", confirmHint: `"version"`, versionKey: "version"},
	{platform: "Jupyter Server", family: "notebook",
		confirmPath: "/api", confirmHint: `"version"`, versionKey: "version",
		authPath: "/api/contents"},
	{platform: "Text Generation Inference", family: "model-runtime",
		confirmPath: "/info", confirmHint: `"model_id"`, versionKey: "version",
		noAuth: true},
	{platform: "OpenAI-compatible model server", family: "model-runtime",
		confirmPath: "/v1/models", confirmHint: `"data"`, noAuth: true},
}

// identify walks the signature table against an open port and fills in the
// Probe's service, family, match confidence, state and evidence. GET / is the
// one universal probe; a platform's own API is the proof. At most a handful of
// requests, all read-only, all to the one port.
func identify(p *Probe, ip, hostname string, port int, timeout time.Duration) {
	client := newHTTPClient(timeout)
	host := ip
	if hostname != "" && net.ParseIP(hostname) == nil {
		host = hostname // a virtual-hosted service needs its name
	}

	for _, scheme := range []string{"http", "https"} {
		base := fmt.Sprintf("%s://%s:%d", scheme, host, port)
		rootStatus, rootHdr, rootBody, ok := httpGet(client, base+"/")
		if !ok {
			continue
		}
		rootText := strings.ToLower(rootHdr + "\n" + rootBody)

		// strong candidates — those GET / hinted at — go first, then the rest
		hinted := map[string]bool{}
		var ordered []llmSignature
		for _, sig := range signatures {
			if sig.rootHint != "" && strings.Contains(rootText, sig.rootHint) {
				ordered = append(ordered, sig)
				hinted[sig.platform] = true
			}
		}
		for _, sig := range signatures {
			if !hinted[sig.platform] {
				ordered = append(ordered, sig)
			}
		}

		const maxConfirm = 6 // intensity cap: one conversation, not a scan
		var soft *llmSignature
		for i := 0; i < len(ordered) && i < maxConfirm; i++ {
			sig := ordered[i]
			cs, _, cbody, cok := httpGet(client, base+sig.confirmPath)
			if cok && cs == 200 && strings.Contains(cbody, sig.confirmHint) {
				fillConfirmed(p, client, base, sig, cbody)
				return
			}
			if hinted[sig.platform] && soft == nil {
				s := sig
				soft = &s
			}
		}

		if soft != nil {
			// the root page resembled this platform but its API never
			// confirmed: a softmatch. Name the family, claim no finding.
			p.Service, p.Family, p.Match = soft.platform, soft.family, MatchTentative
			p.State, p.Severity = StateOther, "INFO"
			p.Evidence = fmt.Sprintf("root page resembles %s; its API (%s) did "+
				"not confirm. Family-level match only.", soft.platform, soft.confirmPath)
			return
		}

		server := headerValue(rootHdr, "Server")
		desc := server
		if desc == "" {
			desc = pageTitle(rootBody)
		}
		if desc == "" {
			desc = fmt.Sprintf("HTTP %d", rootStatus)
		}
		p.Service, p.Family = "web service", "web"
		p.State, p.Severity = StateOther, "INFO"
		p.Evidence = fmt.Sprintf("HTTP %d, %s. Not a recognized AI/LLM platform.",
			rootStatus, desc)
		return
	}

	if b := bannerGrab(ip, port, timeout); b != "" {
		p.Service, p.State, p.Severity = "unidentified", StateOpen, "INFO"
		p.Evidence = "banner: " + b
		return
	}
	p.Service, p.State, p.Severity = "unidentified", StateOpen, "INFO"
	p.Evidence = "TCP open; no HTTP response and no banner. Service not identified."
}

// fillConfirmed records a confirmed platform match and resolves its auth state.
func fillConfirmed(p *Probe, client *http.Client, base string, sig llmSignature, confirmBody string) {
	name := sig.platform
	if sig.versionKey != "" {
		if v := jsonField(confirmBody, sig.versionKey); v != "" && v != "?" {
			name += " " + v
		}
	}
	p.Service, p.Family, p.Match = name, sig.family, MatchConfirmed

	switch {
	case sig.noAuth:
		p.State, p.Severity = StateUnauth, "HIGH"
		p.Evidence = fmt.Sprintf("%s confirmed via %s; the platform ships no "+
			"authentication, so this is unauthenticated access.", name, sig.confirmPath)
	case sig.authPath != "":
		st, _, _, ok := httpGet(client, base+sig.authPath)
		if ok && st == 200 {
			p.State, p.Severity = StateUnauth, "HIGH"
			p.Evidence = fmt.Sprintf("%s confirmed; %s answered 200 with no "+
				"credentials. Unauthenticated access.", name, sig.authPath)
		} else {
			p.State, p.Severity = StateAuth, "LOW"
			p.Evidence = fmt.Sprintf("%s confirmed; %s returned %d. "+
				"Authentication enforced.", name, sig.authPath, st)
		}
	default:
		p.State, p.Severity = StateOther, "INFO"
		p.Evidence = fmt.Sprintf("%s confirmed via %s; auth state not probed.",
			name, sig.confirmPath)
	}
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
