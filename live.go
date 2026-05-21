package main

import (
	"fmt"
	"os"
	"strings"
)

// liveUI renders tiptoe's progress while it runs. tiptoe is slow on purpose —
// the congestion-control pacer can wait two minutes between probes — so a
// static log would look frozen. The live status line makes the controller's
// work visible: you watch it pace, speed up, slow down, and back off in real
// time, with a countdown to the next probe.
//
// One status line at the bottom is rewritten in place; each finished probe
// scrolls above it as a permanent line. When stderr is not a terminal, or for
// a --json run, the status line is suppressed and only the permanent lines
// print — so piped and scripted runs stay clean.
type liveUI struct {
	on    bool // master enable (false for --json)
	tty   bool // stderr is an interactive terminal
	frame int  // spinner animation counter
}

var spinnerFrames = []rune("⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏")

func newLiveUI(enabled bool) *liveUI {
	return &liveUI{on: enabled, tty: enabled && stderrTTY}
}

// header prints the one-time line that opens the live phase.
func (ui *liveUI) header(target, ip string) {
	if !ui.on {
		return
	}
	fmt.Fprintf(os.Stderr, "  %sassessing%s %s (%s)\n",
		sgr(ansiBold), sgr(ansiReset), target, ip)
}

// status rewrites the in-place status line. Called many times per probe to
// animate the spinner and the countdown.
func (ui *liveUI) status(s string) {
	if !ui.tty {
		return
	}
	ui.frame++
	fmt.Fprintf(os.Stderr, "\r\x1b[K  %s%c%s %s",
		sgr(ansiCyan), spinnerFrames[ui.frame%len(spinnerFrames)], sgr(ansiReset), s)
}

// event clears the status line and prints a permanent line above it.
func (ui *liveUI) event(line string) {
	if !ui.on {
		return
	}
	if ui.tty {
		fmt.Fprint(os.Stderr, "\r\x1b[K")
	}
	fmt.Fprintln(os.Stderr, "  "+line)
}

// done clears the status line at the end of the run.
func (ui *liveUI) done() {
	if ui.tty {
		fmt.Fprint(os.Stderr, "\r\x1b[K")
	}
}

// progressBar renders a proportional bar, e.g. ▕██████░░░░░░▏.
func progressBar(frac float64, width int) string {
	if frac < 0 {
		frac = 0
	}
	if frac > 1 {
		frac = 1
	}
	fill := int(frac * float64(width))
	return "▕" + strings.Repeat("█", fill) + strings.Repeat("░", width-fill) + "▏"
}

// probeLine formats a finished probe as a permanent scrollback line. A
// verified-unauthenticated finding is the one result worth a color.
func probeLine(p Probe) string {
	glyph, color := "·", ansiDim
	switch p.State {
	case StateUnauth:
		glyph, color = "!", ansiBold
	case StateAuth, StateVersion:
		glyph, color = "+", ""
	case StateSilent, StateReset:
		glyph, color = "x", ansiDim
	case StateOpen, StateOther:
		glyph, color = "+", ""
	}
	svc := p.Service
	if svc == "" {
		svc = "—"
	}
	rtt := ""
	if p.TCPOpen {
		rtt = fmt.Sprintf("%5.0fms", p.RTTms)
	}
	return fmt.Sprintf("%s%s :%-6d %-30s %-16s %s%s",
		sgr(color), glyph, p.Port, trunc(svc, 30), p.State, rtt, sgr(ansiReset))
}

func trunc(s string, n int) string {
	if len(s) > n {
		return s[:n-1] + "…"
	}
	return s
}
