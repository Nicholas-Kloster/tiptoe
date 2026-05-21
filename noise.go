package main

import (
	"fmt"
	"time"
)

// NoiseReport quantifies how loud a run was. Most scanners never tell you this;
// tiptoe treats noise as a budget you spend. A portscan detector (Snort's
// sfPortscan and its kin) fires on rapid connections to many distinct ports
// from one source — so the two numbers that matter are the count of distinct
// ports touched and the peak connection rate. tiptoe, serialized and paced,
// is structurally quiet; this report proves it instead of asserting it.
type NoiseReport struct {
	Connections  int     `json:"connections"`
	DistinctPorts int    `json:"distinct_ports"`
	WindowSec    float64 `json:"window_seconds"`
	PeakPerMin   float64 `json:"peak_conns_per_min"`
	Verdict      string  `json:"verdict"`
}

// portscanBudget is a deliberately conservative estimate of how many
// distinct-port connections within a rolling minute a typical IPS portscan
// rule tolerates before it flags the source. Real thresholds vary by sensor
// and tuning; tiptoe uses this only to render a budget gauge, never to make a
// safety guarantee.
const portscanBudget = 10.0

type connEvent struct {
	port int
	at   time.Time
}

type noiseTracker struct {
	events []connEvent
}

func (n *noiseTracker) record(port int) {
	n.events = append(n.events, connEvent{port: port, at: time.Now()})
}

// peakPerMin returns the largest number of connections observed inside any
// 60-second sliding window — the figure a rate-based detector reacts to.
func (n *noiseTracker) peakPerMin() float64 {
	peak := 0
	for i := range n.events {
		count := 0
		for j := i; j < len(n.events); j++ {
			if n.events[j].at.Sub(n.events[i].at) <= time.Minute {
				count++
			} else {
				break
			}
		}
		if count > peak {
			peak = count
		}
	}
	return float64(peak)
}

func (n *noiseTracker) report() NoiseReport {
	r := NoiseReport{Connections: len(n.events)}
	if len(n.events) == 0 {
		r.Verdict = "no active probes sent"
		return r
	}
	distinct := map[int]bool{}
	for _, e := range n.events {
		distinct[e.port] = true
	}
	r.DistinctPorts = len(distinct)
	r.WindowSec = n.events[len(n.events)-1].at.Sub(n.events[0].at).Seconds()
	r.PeakPerMin = n.peakPerMin()

	pct := r.PeakPerMin / portscanBudget * 100
	switch {
	case pct <= 40:
		r.Verdict = fmt.Sprintf("quiet — peak %.0f conn/min, ~%.0f%% of a "+
			"portscan-detection budget", r.PeakPerMin, pct)
	case pct <= 80:
		r.Verdict = fmt.Sprintf("moderate — peak %.0f conn/min, ~%.0f%% of a "+
			"portscan-detection budget; consider longer pacing", r.PeakPerMin, pct)
	default:
		r.Verdict = fmt.Sprintf("LOUD — peak %.0f conn/min, ~%.0f%% of a "+
			"portscan-detection budget; this run risks a scan flag", r.PeakPerMin, pct)
	}
	return r
}
