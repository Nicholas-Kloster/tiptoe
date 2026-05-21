package main

import (
	"slices"
	"time"
)

// canaryPorts are mundane, near-always-listening ports. tiptoe probes one of
// these first when it can: a clean, fast service gives the pacer an honest
// baseline RTT to measure every later probe against. Starting the baseline on
// a slow application port would bias the whole Vegas calculation.
var canaryPorts = map[int]bool{22: true, 80: true, 443: true}

// orderProbes decides the probe sequence. A canary port goes first to seed the
// pacer's baseline RTT; the rest follow in ascending order. Ascending order is
// itself mildly stealthier than random — it does not look like a tool walking
// a service list.
func orderProbes(ports []int) []int {
	in := append([]int(nil), ports...)
	slices.Sort(in)
	var canary int
	rest := make([]int, 0, len(in))
	for _, p := range in {
		if canary == 0 && canaryPorts[p] {
			canary = p
			continue
		}
		rest = append(rest, p)
	}
	if canary != 0 {
		return append([]int{canary}, rest...)
	}
	return rest
}

// runAssessment is phase 1: the paced, block-aware active loop. Each iteration
// waits for the pacer, sends exactly one probe, feeds the outcome back to the
// pacer, and stops the instant the pacer concludes the host has filtered us.
// The loop is deliberately serial — one connection at a time. Parallel
// multi-port connections ARE the scan signature; serialization is the point.
func runAssessment(in Intel, ports []int, timeout time.Duration, pacer *Pacer) Assessment {
	a := Assessment{
		Target:    in.Input,
		StartedAt: time.Now().UTC().Format(time.RFC3339),
		Intel:     in,
	}
	seq := orderProbes(ports)
	a.Planned = len(seq)
	noise := &noiseTracker{}

	for i, port := range seq {
		if i > 0 {
			pacer.Wait() // congestion-controlled delay — may be 8s or 2min
		}
		noise.record(port)
		pr := probePort(in.IP, in.Input, port, timeout)
		a.Probes = append(a.Probes, pr)

		pacer.Observe(port, pr.RTT, !pr.TCPOpen, pr.State == StateReset)
		if pacer.Blocked() {
			a.Blocked = true
			a.BlockedReason = pacer.BlockReason()
			a.BlockedAtProbe = i + 1
			break
		}
	}

	a.Noise = noise.report()
	a.PacerTrace = pacer.Trace()
	return a
}
