// Command tiptoe is a quiet, block-aware assessor for AI/LLM infrastructure.
//
// The NuClide arsenal is built for population sweeps — aimap, menlohunt and the
// rest spread their load over thousands of hosts, so no single host ever sees
// a scan signature. Concentrate those tools on ONE monitored host and they go
// loud: the host's IPS flags the scan and every tool after it runs blind
// against a now-filtered target.
//
// tiptoe is the quiet counterpart. It is passive-first (the recon phase sends
// the target zero packets), it probes serially and paced by a TCP-style
// congestion controller, and it watches its own probe outcomes so it can tell
// when it has been filtered — and stop, instead of hammering a dark host.
package main

import (
	"flag"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"
)

const version = "0.1.0"

// ANSI styling. Emitted only when stderr is a real terminal, so a piped or
// redirected run stays clean.
const (
	ansiReset = "\x1b[0m"
	ansiCyan  = "\x1b[36m"
	ansiBold  = "\x1b[1m"
	ansiDim   = "\x1b[2m"
)

var stderrTTY = func() bool {
	fi, err := os.Stderr.Stat()
	return err == nil && fi.Mode()&os.ModeCharDevice != 0
}()

func sgr(code string) string {
	if stderrTTY {
		return code
	}
	return ""
}

// printBanner writes the tiptoe banner to stderr — stdout is left clean so
// `--json` output is never polluted.
func printBanner() {
	fmt.Fprint(os.Stderr, sgr(ansiCyan)+`
   _   _      _
  | |_(_)_ __| |_ ___  ___
  | __| | '_ \ __/ _ \/ -_)
   \__|_| .__/\__\___/\___|
        |_|`+sgr(ansiReset)+sgr(ansiDim)+`   v`+version+`  ·  NuClide Research`+
		sgr(ansiReset)+`

`+sgr(ansiBold)+`   quiet, block-aware assessment for AI/LLM infrastructure`+
		sgr(ansiReset)+`
`+sgr(ansiDim)+`   the arsenal goes loud across thousands of hosts;
   tiptoe assesses the one host that watches back.`+sgr(ansiReset)+"\n")
}

func usage() {
	printBanner()
	fmt.Fprint(os.Stderr, `
usage:
  tiptoe assess  <host>   passive intel, then congestion-controlled active probing
  tiptoe passive <host>   passive intel only, zero packets to the target
  tiptoe version          print the version and exit

assess flags:
  --ports <csv>     ports to probe (default: ports from passive intel)
  --timeout <dur>   per-probe timeout (default 10s)
  --json            emit JSON instead of the human report
  --passive-only    skip the active phase

examples:
  tiptoe assess  manglillo.example.edu
  tiptoe assess  10.0.0.1 --ports 8000,8888 --json
  tiptoe passive lab.example.edu

`)
}

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	switch os.Args[1] {
	case "assess":
		runCmd(os.Args[2:], false)
	case "passive":
		runCmd(os.Args[2:], true)
	case "version", "-v", "--version":
		fmt.Printf("tiptoe %s\n", version)
	case "help", "-h", "--help":
		usage()
	default:
		fmt.Fprintf(os.Stderr, "tiptoe: unknown command %q\n\n", os.Args[1])
		usage()
		os.Exit(2)
	}
}

func runCmd(args []string, passiveOnly bool) {
	name := "assess"
	if passiveOnly {
		name = "passive"
	}
	fs := flag.NewFlagSet(name, flag.ExitOnError)
	jsonOut := fs.Bool("json", false, "emit JSON")
	portsCSV := fs.String("ports", "", "comma-separated ports to probe")
	timeout := fs.Duration("timeout", 10*time.Second, "per-probe timeout")
	forcePassive := fs.Bool("passive-only", false, "skip the active phase")
	// The stdlib flag package stops parsing at the first non-flag argument,
	// so `tiptoe assess host --json` would silently leave --json unparsed.
	// Parse once, lift out the host, then parse whatever flags followed it.
	_ = fs.Parse(args)
	rest := fs.Args()
	if len(rest) == 0 {
		fmt.Fprintf(os.Stderr, "tiptoe %s: need a host\n", name)
		os.Exit(2)
	}
	host := rest[0]
	if len(rest) > 1 {
		_ = fs.Parse(rest[1:])
	}
	if passiveOnly {
		*forcePassive = true
	}

	if !*jsonOut {
		printBanner()
	}
	fmt.Fprintf(os.Stderr, "[*] passive intel — %s\n", host)

	intel, err := gatherIntel(host)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[!] %v\n", err)
		os.Exit(1)
	}
	fmt.Fprintf(os.Stderr, "[+] %s -> %s\n", host, intel.IP)
	if len(intel.ShodanPorts) > 0 {
		fmt.Fprintf(os.Stderr, "[+] Shodan: org=%q ports=%v\n",
			intel.ShodanOrg, intel.ShodanPorts)
	}

	a := Assessment{
		Target:    host,
		StartedAt: time.Now().UTC().Format(time.RFC3339),
		Intel:     intel,
	}

	if !*forcePassive {
		ports := parsePorts(*portsCSV)
		if len(ports) == 0 {
			ports = intel.ShodanPorts
		}
		if len(ports) == 0 {
			fmt.Fprintln(os.Stderr, "[!] no ports to probe — pass --ports, "+
				"or the host has no passive footprint")
		} else {
			fmt.Fprintf(os.Stderr, "[*] active phase — %d port(s), serialized, "+
				"congestion-controlled pacing\n\n", len(ports))
			a = runAssessment(intel, ports, *timeout, NewPacer(), !*jsonOut)
		}
	}

	if *jsonOut {
		printJSON(a)
	} else {
		printReport(a)
	}
}

// parsePorts parses a comma-separated port list, silently skipping junk.
func parsePorts(csv string) []int {
	var out []int
	for _, f := range strings.Split(csv, ",") {
		f = strings.TrimSpace(f)
		if f == "" {
			continue
		}
		if n, err := strconv.Atoi(f); err == nil && n > 0 && n < 65536 {
			out = append(out, n)
		}
	}
	return out
}
