package main

import (
	"fmt"
	"slices"
	"time"
)

// canaryPorts are mundane, near-always-listening ports. tiptoe probes one of
// these first when it can: a clean, fast service gives the pacer an honest
// baseline RTT to measure every later probe against. Seeding the baseline on a
// slow application port would bias the whole suspicion calculation.
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
func runAssessment(in Intel, ports []int, timeout time.Duration, pacer *Pacer, live bool) Assessment {
	a := Assessment{
		Target:    in.Input,
		StartedAt: time.Now().UTC().Format(time.RFC3339),
		Intel:     in,
	}
	seq := orderProbes(ports)
	a.Planned = len(seq)
	noise := &noiseTracker{}
	ui := newLiveUI(live)
	ui.header(in.Input, in.IP)

	for i, port := range seq {
		if i > 0 {
			countdown(ui, pacer, i+1, len(seq), port) // congestion-controlled wait
		}
		ui.status(fmt.Sprintf("probe %d/%d  ·  :%d  probing…", i+1, len(seq), port))

		noise.record(port)
		pr := probePort(in.IP, in.Input, port, timeout)
		a.Probes = append(a.Probes, pr)
		pacer.Observe(port, pr.RTT, !pr.TCPOpen, pr.State == StateReset)
		ui.event(probeLine(pr))

		if pacer.Blocked() {
			a.Blocked = true
			a.BlockedReason = pacer.BlockReason()
			a.BlockedAtProbe = i + 1
			ui.event(sgr(ansiBold) + "[!] block detected — host filtered us, halting" +
				sgr(ansiReset))
			break
		}
	}

	ui.done()
	a.Noise = noise.report()
	a.PacerTrace = pacer.Trace()
	return a
}

// countdown performs the congestion-controlled wait before a probe. On a
// terminal it animates a live countdown so the pacing is visible rather than a
// frozen pause; otherwise it just sleeps.
func countdown(ui *liveUI, pacer *Pacer, probeNum, total, nextPort int) {
	delay := pacer.NextDelay()
	if !ui.tty {
		time.Sleep(delay)
		return
	}
	info := pacerSummary(pacer)
	deadline := time.Now().Add(delay)
	for {
		rem := time.Until(deadline)
		if rem <= 0 {
			break
		}
		frac := 1 - rem.Seconds()/delay.Seconds()
		ui.status(fmt.Sprintf("probe %d/%d  ·  next :%d in %2.0fs %s  ·  %s",
			probeNum, total, nextPort, rem.Seconds()+0.5,
			progressBar(frac, 12), info))
		time.Sleep(200 * time.Millisecond)
	}
}

// pacerSummary is a short live-display string of the pacer's last decision.
func pacerSummary(pacer *Pacer) string {
	tr := pacer.Trace()
	if len(tr) == 0 {
		return "pacer warming up"
	}
	s := tr[len(tr)-1]
	if s.Phi > 0 {
		return fmt.Sprintf("pacer %.0fs · phi %.2f · %s", s.IntervalS, s.Phi, s.Action)
	}
	return fmt.Sprintf("pacer %.0fs · %s", s.IntervalS, s.Action)
}
