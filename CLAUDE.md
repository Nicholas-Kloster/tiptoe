# tiptoe

Quiet, block-aware assessment for AI/LLM infrastructure. The NuClide arsenal
(aimap, menlohunt) is built for population sweeps where load spreads over
thousands of hosts. tiptoe is the quiet counterpart for the single monitored
host: passive-first recon that sends the target zero packets, serialized active
probing paced by a TCP-style congestion controller, and block detection that
halts the run when the host filters the source instead of hammering a dark host.

## Language
Go (single binary, standard library only, Go 1.22+)

## Build & Run
```
go build -o tiptoe .

./tiptoe assess  <host>                     # passive intel, then paced active probing
./tiptoe passive <host>                     # passive intel only, zero packets to the host
./tiptoe assess  <host> --ports 8000,8888   # probe a specific port set
./tiptoe assess  <host> --json              # machine-readable output for the chain
```

## Layout
```
main.go      CLI entry + subcommand dispatch
passive.go   phase 0 — passive intel (Shodan host API, reverse DNS, crt.sh)
pacer.go     the congestion-control pacing engine — the novel core
probe.go     phase 1 — quiet active probes, one connection per port
assess.go    the paced, block-aware assessment loop
noise.go     the noise-budget tracker
report.go    human-readable and JSON output
types.go     shared types
```

## Claude Code Notes
- pacer.go is the load-bearing idea. It models a stealth assessment as a flow
  to be rate-controlled: TCP Vegas delay-gradient sensing to back off before a
  block, TCP Reno multiplicative decrease on a lost probe, and deliberately no
  slow start (a stealth probe must never find the ceiling). The file's header
  comment carries the full mapping.
- JSON output is shaped to pipe into `visorlog ingest`.
- Active probes are read-only marker probes. tiptoe never sends a credential.
- Built with [Claude Code](https://claude.com/claude-code).
