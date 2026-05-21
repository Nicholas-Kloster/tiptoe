package main

import (
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"
)

// gatherIntel runs phase 0. It builds a port and service picture of the host
// WITHOUT sending the host a single packet. Every source here is a third party
// that already did the looking: a DNS resolver, Shodan's cached crawl, the
// certificate-transparency logs. The cheapest probe is the one you never send.
func gatherIntel(input string) (Intel, error) {
	in := Intel{Input: input}

	if ip := net.ParseIP(input); ip != nil {
		in.IP = ip.String()
	} else {
		ips, err := net.LookupIP(input)
		if err != nil || len(ips) == 0 {
			return in, fmt.Errorf("cannot resolve %q", input)
		}
		for _, ip := range ips {
			if v4 := ip.To4(); v4 != nil {
				in.IP = v4.String()
				break
			}
		}
		if in.IP == "" {
			in.IP = ips[0].String()
		}
	}

	if names, err := net.LookupAddr(in.IP); err == nil {
		for _, n := range names {
			in.PTR = append(in.PTR, strings.TrimSuffix(n, "."))
		}
	}

	shodanHost(&in)

	if net.ParseIP(input) == nil {
		in.CTNames = crtSh(input)
	}
	return in, nil
}

func httpGetJSON(url string, timeout time.Duration, into any) bool {
	client := &http.Client{Timeout: timeout}
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return false
	}
	req.Header.Set("User-Agent", "tiptoe/"+version)
	resp, err := client.Do(req)
	if err != nil {
		return false
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return false
	}
	return json.NewDecoder(resp.Body).Decode(into) == nil
}

// shodanHost reads Shodan's cached record for the IP. Shodan already crawled
// the host; tiptoe reads that memory instead of re-crawling.
func shodanHost(in *Intel) {
	home, err := os.UserHomeDir()
	if err != nil {
		return
	}
	keyBytes, err := os.ReadFile(filepath.Join(home, ".shodan", "api_key"))
	if err != nil {
		return
	}
	key := strings.TrimSpace(string(keyBytes))
	if key == "" {
		return
	}

	var sh struct {
		Org        string `json:"org"`
		OS         string `json:"os"`
		Ports      []int  `json:"ports"`
		LastUpdate string `json:"last_update"`
		Vulns      []string `json:"vulns"`
		Data       []struct {
			Port    int    `json:"port"`
			Product string `json:"product"`
		} `json:"data"`
	}
	url := fmt.Sprintf("https://api.shodan.io/shodan/host/%s?key=%s", in.IP, key)
	if !httpGetJSON(url, 20*time.Second, &sh) {
		return
	}
	slices.Sort(sh.Ports)
	in.ShodanOrg, in.ShodanOS = sh.Org, sh.OS
	in.ShodanPorts, in.ShodanSeen = sh.Ports, sh.LastUpdate
	slices.Sort(sh.Vulns)
	in.ShodanVulns = sh.Vulns
	in.ShodanSvc = map[string]string{}
	for _, d := range sh.Data {
		if d.Product != "" {
			in.ShodanSvc[fmt.Sprintf("%d", d.Port)] = d.Product
		}
	}
}

// crtSh queries certificate-transparency logs for names sharing the domain.
// The query hits crt.sh, never the target.
func crtSh(domain string) []string {
	var rows []struct {
		NameValue string `json:"name_value"`
	}
	url := "https://crt.sh/?q=" + domain + "&output=json"
	if !httpGetJSON(url, 25*time.Second, &rows) {
		return nil
	}
	seen := map[string]bool{}
	for i, r := range rows {
		if i >= 300 {
			break
		}
		for _, n := range strings.Split(r.NameValue, "\n") {
			n = strings.ToLower(strings.TrimSpace(strings.TrimPrefix(n, "*.")))
			if n != "" {
				seen[n] = true
			}
		}
	}
	out := make([]string, 0, len(seen))
	for n := range seen {
		out = append(out, n)
	}
	slices.Sort(out)
	if len(out) > 40 {
		out = out[:40]
	}
	return out
}
