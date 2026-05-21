package main

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
)

func firstN[T any](s []T, n int) []T {
	if len(s) > n {
		return s[:n]
	}
	return s
}

// printJSON emits the assessment as machine-readable JSON — pipe it into
// visorlog ingest, or anything else in the chain.
func printJSON(a Assessment) {
	b, err := json.MarshalIndent(a, "", "  ")
	if err != nil {
		fmt.Fprintln(os.Stderr, "json:", err)
		return
	}
	fmt.Println(string(b))
}

// printReport renders the human-readable assessment.
func printReport(a Assessment) {
	rule := strings.Repeat("=", 72)
	fmt.Println("\n" + rule)
	fmt.Printf("TIPTOE — %s (%s)\n", a.Target, a.Intel.IP)
	fmt.Println(rule)

	in := a.Intel
	fmt.Println("\n  passive intel (zero packets to target):")
	if in.ShodanOrg != "" {
		fmt.Printf("    org        : %s\n", in.ShodanOrg)
	}
	if len(in.PTR) > 0 {
		fmt.Printf("    ptr        : %s\n", strings.Join(in.PTR, ", "))
	}
	if len(in.ShodanPorts) > 0 {
		fmt.Printf("    shodan     : ports %v  (crawled %s)\n",
			in.ShodanPorts, in.ShodanSeen)
	} else {
		fmt.Println("    shodan     : no cached record")
	}
	if len(in.ShodanVulns) > 0 {
		fmt.Printf("    cve (cached): %s\n",
			strings.Join(firstN(in.ShodanVulns, 12), ", "))
	}
	if len(in.CTNames) > 0 {
		fmt.Printf("    ct names   : %s\n", strings.Join(firstN(in.CTNames, 8), ", "))
	}

	if len(a.Probes) == 0 {
		fmt.Println("\n  active phase: not run")
	} else {
		fmt.Printf("\n  active probes — %d of %d planned, each active-verified:\n",
			len(a.Probes), a.Planned)
		for _, p := range a.Probes {
			if p.TCPOpen {
				svc := p.Service
				if svc == "" {
					svc = "unidentified"
				}
				fmt.Printf("    :%-6d %-22s [%s]  %.0fms\n",
					p.Port, svc, p.State, p.RTTms)
				if p.Evidence != "" {
					fmt.Printf("             %s\n", p.Evidence)
				}
			} else {
				fmt.Printf("    :%-6d %-22s [%s]\n", p.Port, "—", p.State)
			}
		}
	}

	if len(a.PacerTrace) > 0 {
		fmt.Println("\n  pacer trace (congestion control + phi-accrual suspicion):")
		for _, s := range a.PacerTrace {
			switch s.Action {
			case actBackoff, actBlock:
				fmt.Printf("    #%-2d :%-6d  silent            -> %-9s interval %.0fs\n",
					s.Probe, s.Port, s.Action, s.IntervalS)
			case actRefused:
				fmt.Printf("    #%-2d :%-6d  RST (port closed) -> %-9s\n",
					s.Probe, s.Port, s.Action)
			case actBaseline:
				fmt.Printf("    #%-2d :%-6d  %.0fms              -> baseline (detector learning)\n",
					s.Probe, s.Port, s.RTTms)
			default:
				fmt.Printf("    #%-2d :%-6d  %.0fms/mean %.0fms  phi %.2f -> %-9s interval %.0fs\n",
					s.Probe, s.Port, s.RTTms, s.MeanRTTms, s.Phi,
					s.Action, s.IntervalS)
			}
		}
	}

	fmt.Println("\n  " + strings.Repeat("-", 68))
	if a.Blocked {
		fmt.Printf("  [!] BLOCKED at probe %d of %d\n", a.BlockedAtProbe, a.Planned)
		fmt.Printf("      %s\n", a.BlockedReason)
		fmt.Printf("      %d port(s) left unprobed on purpose — re-probing a host\n",
			a.Planned-len(a.Probes))
		fmt.Println("      that has filtered you only deepens the block. Cool down, retry later.")
	} else if len(a.Probes) > 0 {
		fmt.Printf("  [+] completed all %d probes — no block detected.\n", len(a.Probes))
	}
	if a.Noise.Verdict != "" {
		fmt.Printf("  noise: %s\n", a.Noise.Verdict)
	}
}
