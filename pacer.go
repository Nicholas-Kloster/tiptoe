package main

import (
	"math/rand/v2"
	"time"
)

// Pacer is tiptoe's congestion-control engine. It treats a stealth assessment
// as a flow to be rate-controlled, and combines two bodies of theory.
//
// From TCP congestion control:
//
//   - TCP Vegas — delay-gradient sensing. Vegas watches round-trip time and
//     reads a rising RTT as a queue building, slowing down BEFORE a packet is
//     dropped. tiptoe does the same: a host whose answers are slowing is
//     starting to throttle us, and tiptoe backs off proactively.
//
//   - TCP Reno — multiplicative decrease. A lost probe (a silent drop, or a
//     RST) is treated like a lost segment: the probe rate is cut hard.
//
// tiptoe deliberately does NOT take slow start from TCP. A bulk transfer ramps
// up exponentially because it wants to find the bandwidth ceiling fast. A
// stealth probe wants the opposite — to never touch the ceiling. So the
// control variable here is an inter-probe INTERVAL, the inverse of TCP's
// congestion window: it grows when cwnd would shrink, starts cautious, and
// only earns speed.
//
// From distributed-systems failure detection:
//
//   - The phi-accrual detector (see suspicion.go) replaces what would
//     otherwise be a fixed "RTT is too high" threshold. Vegas knew RTT was
//     rising; phi-accrual knows, against a LEARNED distribution of the host's
//     own behaviour, how surprising that rise is. The pacer's slow-down and
//     speed-up decisions are driven by that suspicion score, so the controller
//     adapts to a jittery host and a steady host without retuning.
type Pacer struct {
	// configuration
	baseInterval time.Duration // the interval a run starts at
	minInterval  time.Duration // floor — tiptoe never probes faster than this
	maxInterval  time.Duration // ceiling — a fully backed-off interval
	step         time.Duration // additive increase/decrease unit
	jitter       float64       // ± fraction of randomization on every Wait
	phiLow       float64       // suspicion below this: host calm, speed up
	phiHigh      float64       // suspicion above this: host stressed, slow down
	backoff      float64       // multiplicative interval blow-up on a lost probe
	blockAfter   int           // consecutive losses that mean "blocked", not "slow"

	// live state
	susp       *suspicion // phi-accrual detector over the host's RTTs
	interval   time.Duration
	consecLoss int
	probes     int
	blocked    bool
	blockMsg   string
	trace      []PacerSnap
}

// PacerSnap is one entry in the control trace — what the pacer saw and decided
// after each probe. The trace makes the controller's reasoning auditable.
type PacerSnap struct {
	Probe     int     `json:"probe"`
	Port      int     `json:"port"`
	RTTms     float64 `json:"rtt_ms"`
	MeanRTTms float64 `json:"mean_rtt_ms"`
	Phi       float64 `json:"phi"`
	IntervalS float64 `json:"interval_s"`
	Action    string  `json:"action"`
}

// Pacer actions, recorded in the trace.
const (
	actSpeedUp  = "speed-up"  // suspicion low — additive decrease of the interval
	actSlowDown = "slow-down" // suspicion high — proactive additive increase
	actHold     = "hold"      // suspicion in the neutral band
	actBackoff  = "backoff"   // a probe was lost — multiplicative increase
	actBlock    = "block"     // losses persisted through backoff — host filtered us
	actBaseline = "baseline"  // detector still learning the host's normal RTT
)

// NewPacer returns a Pacer tuned for stealth: cautious start, slow floor,
// proactive backoff. Every default biases quiet over fast.
func NewPacer() *Pacer {
	return &Pacer{
		baseInterval: 12 * time.Second,
		minInterval:  8 * time.Second,
		maxInterval:  120 * time.Second,
		step:         4 * time.Second,
		jitter:       0.3,
		phiLow:       0.5, // RTT at or below the host's learned baseline
		phiHigh:      1.5, // RTT well out in the tail — the host is slowing us
		backoff:      2.0,
		blockAfter:   3,
		susp:         newSuspicion(20),
		interval:     12 * time.Second,
	}
}

// Wait sleeps for the current interval, randomized by ±jitter. A perfectly
// periodic probe train is itself a signature; the jitter breaks the cadence.
func (p *Pacer) Wait() {
	d := float64(p.interval) * (1 + (rand.Float64()*2-1)*p.jitter)
	time.Sleep(time.Duration(d))
}

// Observe feeds the pacer one probe outcome and updates the control state.
// lost is true when the probe got no answer (a silent drop); reset is true
// when the host sent a TCP RST. Both count as a lost segment; a RST, the
// louder signal, is backed off harder.
func (p *Pacer) Observe(port int, rtt time.Duration, lost, reset bool) {
	p.probes++
	snap := PacerSnap{Probe: p.probes, Port: port}

	if lost {
		p.consecLoss++
		factor := p.backoff
		if reset {
			factor *= 1.5 // an active refusal is a stronger "you are noticed"
		}
		p.interval = clampDur(time.Duration(float64(p.interval)*factor),
			p.minInterval, p.maxInterval)
		snap.Action = actBackoff
		if p.consecLoss >= p.blockAfter {
			p.blocked = true
			snap.Action = actBlock
			p.blockMsg = "host stopped answering and stayed silent through the " +
				"pacer's full backoff — it has filtered us, not merely slowed"
		}
		snap.IntervalS = p.interval.Seconds()
		p.trace = append(p.trace, snap)
		return
	}

	// a good probe — clear the loss streak and feed the suspicion detector
	p.consecLoss = 0
	rttMs := rtt.Seconds() * 1000
	p.susp.observe(rttMs)
	mean, _ := p.susp.stats()
	snap.RTTms = rttMs
	snap.MeanRTTms = mean

	if !p.susp.ready() {
		// not enough samples yet — hold the interval, keep learning the host
		snap.Action = actBaseline
		snap.IntervalS = p.interval.Seconds()
		p.trace = append(p.trace, snap)
		return
	}

	phi := p.susp.phi(rttMs)
	snap.Phi = phi
	switch {
	case phi < p.phiLow:
		// the host is answering at or under its own baseline — earn some speed
		p.interval = clampDur(p.interval-p.step, p.minInterval, p.maxInterval)
		snap.Action = actSpeedUp
	case phi > p.phiHigh:
		// this answer sits far out in the host's RTT distribution. The host is
		// slowing us. Back off now, before the hard block — the Vegas instinct.
		p.interval = clampDur(p.interval+p.step, p.minInterval, p.maxInterval)
		snap.Action = actSlowDown
	default:
		snap.Action = actHold
	}
	snap.IntervalS = p.interval.Seconds()
	p.trace = append(p.trace, snap)
}

// Blocked reports whether the pacer has concluded the host is filtering us.
func (p *Pacer) Blocked() bool { return p.blocked }

// BlockReason returns the human explanation for a detected block.
func (p *Pacer) BlockReason() string { return p.blockMsg }

// Trace returns the full per-probe control trace.
func (p *Pacer) Trace() []PacerSnap { return p.trace }

func clampDur(d, lo, hi time.Duration) time.Duration {
	if d < lo {
		return lo
	}
	if d > hi {
		return hi
	}
	return d
}
