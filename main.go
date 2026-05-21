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

const banner = `
  _   _       _
 | |_(_)_ __ | |_ ___   ___
 | __| | '_ \| __/ _ \ / _ \
 | |_| | |_) | || (_) |  __/
  \__|_| .__/ \__\___/ \___|   quiet, block-aware AI-infra assessment
       |_|                     v%s · NuClide Research
`

func usage() {
	fmt.Fprintf(os.Stderr, banner, version)
	fmt.Fprint(os.Stderr, `
usage:
  tiptoe assess  <host>   passive intel, then congestion-controlled active probing
  tiptoe passive <host>   passive intel only — zero packets to the target
  tiptoe version

assess flags:
  --ports <csv>     ports to probe (default: ports from passive intel)
  --timeout <dur>   per-probe timeout (default 10s)
  --json            emit JSON instead of the human report
  --passive-only    skip the active phase

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
	_ = fs.Parse(args)

	if fs.NArg() < 1 {
		fmt.Fprintf(os.Stderr, "tiptoe %s: need a host\n", name)
		os.Exit(2)
	}
	host := fs.Arg(0)
	if passiveOnly {
		*forcePassive = true
	}

	if !*jsonOut {
		fmt.Fprintf(os.Stderr, banner, version)
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
				"congestion-controlled pacing\n", len(ports))
			a = runAssessment(intel, ports, *timeout, NewPacer())
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
