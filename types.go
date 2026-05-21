package main

import "time"

// Provenance records HOW a fact about the host is known. A Shodan-cached
// banner and a service tiptoe completed a handshake with this run are not the
// same claim — one may be weeks stale, the other is live. Every reported fact
// carries its provenance so a reader never confuses the two.
type Provenance string

const (
	// ProvPassive — observed by Shodan or certificate transparency. Zero
	// packets were sent to the target to learn it. May be stale.
	ProvPassive Provenance = "passive-cached"
	// ProvActive — tiptoe completed the protocol exchange itself, this run.
	ProvActive Provenance = "active-verified"
)

// Intel is the phase-0 passive picture: everything tiptoe can learn about a
// host WITHOUT sending it a single packet. Built from resolver lookups,
// Shodan's cached crawl, and certificate-transparency logs.
type Intel struct {
	Input       string         `json:"input"`
	IP          string         `json:"ip"`
	PTR         []string       `json:"ptr,omitempty"`
	ShodanOrg   string         `json:"shodan_org,omitempty"`
	ShodanOS    string         `json:"shodan_os,omitempty"`
	ShodanPorts []int          `json:"shodan_ports,omitempty"`
	ShodanSvc   map[string]string `json:"shodan_services,omitempty"`
	ShodanVulns []string       `json:"shodan_vulns,omitempty"`
	ShodanSeen  string         `json:"shodan_last_seen,omitempty"`
	CTNames     []string       `json:"ct_names,omitempty"`
}

// Probe is the outcome of one active probe of one port. RTT is the
// load-bearing field: it is the feedback signal the congestion-control pacer
// reads to decide whether the host is starting to throttle us.
type Probe struct {
	Port       int           `json:"port"`
	Service    string        `json:"service,omitempty"`
	Family     string        `json:"family,omitempty"`
	Match      string        `json:"match,omitempty"`
	TCPOpen    bool          `json:"tcp_open"`
	RTT        time.Duration `json:"-"`
	RTTms      float64       `json:"rtt_ms"`
	State      string        `json:"state"`
	Severity   string        `json:"severity,omitempty"`
	Evidence   string        `json:"evidence,omitempty"`
	Provenance Provenance    `json:"provenance"`
}

// Match confidence — borrowed from nmap's service-detection engine. A
// confirmed match means the platform's own API contract was spoken and
// answered; a tentative match is a soft signal only (nmap's "softmatch") —
// the family is likely but unproven. tiptoe never reports a finding off a
// tentative match: claim only what the response proves (Insight #51).
const (
	MatchConfirmed = "confirmed"
	MatchTentative = "tentative"
)

// Probe states.
const (
	StateUnauth   = "VERIFIED_UNAUTH"   // service confirmed, no authentication
	StateAuth     = "VERIFIED_AUTH"     // service confirmed, authentication enforced
	StateVersion  = "VERSION_DISCLOSED" // service confirmed via banner only
	StateOther    = "VERIFIED_OTHER"    // a service answered, but not the expected one
	StateOpen     = "TCP_OPEN"          // port accepts TCP; service not identified
	StateSilent   = "SILENT"            // no TCP handshake — dropped (filtered)
	StateReset    = "RESET"             // TCP RST — actively refused
)

// Assessment is one full tiptoe run.
type Assessment struct {
	Target         string      `json:"target"`
	StartedAt      string      `json:"started_at"`
	Intel          Intel       `json:"intel"`
	Probes         []Probe     `json:"probes"`
	Blocked        bool        `json:"blocked"`
	BlockedReason  string      `json:"blocked_reason,omitempty"`
	BlockedAtProbe int         `json:"blocked_at_probe,omitempty"`
	Planned        int         `json:"ports_planned"`
	Noise          NoiseReport `json:"noise"`
	PacerTrace     []PacerSnap `json:"pacer_trace"`
}
