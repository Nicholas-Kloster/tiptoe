# tiptoe

**Quiet, block-aware assessment for AI/LLM infrastructure.** A single Go binary.

aimap and menlohunt go loud across thousands of hosts. tiptoe goes quiet
against the one host that is watching back.

---

## The problem tiptoe solves

The NuClide arsenal is built for population sweeps. Load spreads over thousands
of hosts, so no single host ever sees a scan signature. Point those same tools
at ONE monitored host and the economics invert. A 1,000-port `nmap` sweep or a
40-port fingerprint scan, concentrated on a single target, is a textbook scan
signature. A university or enterprise IPS flags it and filters the source. Then
every tool that runs after the loud one probes a host that has gone dark, and
the scan reports "no open ports" — a false negative, presented as a finding.

That failure is not a bug in any one tool. It is a missing capability: the
arsenal has no quiet mode. tiptoe is that mode.

## What tiptoe does differently

**Passive-first.** The reconnaissance phase sends the target zero packets. It
reads Shodan's cached crawl, reverse DNS, and certificate-transparency logs.
The port and service picture is built before a single packet reaches the host.
The cheapest probe is the one you never send.

**Serialized and paced.** One probe at a time. Never a port scan. Parallel
multi-port connections are the scan signature that portscan detectors fire on,
so tiptoe does not make them.

**Congestion-controlled.** The pacing is not a fixed delay. tiptoe models a
stealth assessment as a flow to be rate-controlled, and borrows from TCP.

**Block-aware.** tiptoe watches its own probe outcomes. Once a host has
answered and then goes silent, tiptoe concludes it has been filtered and stops.
It does not keep hammering a dark host. That only deepens the block and
manufactures a misleading null.

## Stealth as congestion control

tiptoe's pacer takes two ideas from forty years of TCP congestion control and
deliberately rejects a third.

**From TCP Vegas: delay-gradient sensing.** Vegas watches round-trip time and
reads a rising RTT as a queue building in the network. It slows down before a
packet is ever dropped. tiptoe does the same. A host whose connect and
handshake times are creeping up above their baseline is starting to throttle
us. tiptoe reads that gradient and backs off proactively, before the hard
block.

**From TCP Reno: multiplicative decrease.** A lost probe, a silent drop or a
TCP RST, is treated like a lost segment. The probe rate is cut hard, not
trimmed. A RST is the louder signal of the two and is backed off harder.

**Not from TCP: slow start.** A bulk transfer ramps up exponentially because
its goal is to find the bandwidth ceiling fast. A stealth probe's goal is the
opposite: never touch the ceiling at all. So tiptoe's control variable is an
inter-probe interval, the inverse of TCP's congestion window. It grows when
cwnd would shrink, it starts deliberately cautious, and it only earns speed.

Every probe is logged in a pacer trace that shows the controller's reasoning:
the measured RTT, the baseline, the ratio between them, and the decision.

## Build

```
go build -o tiptoe .
```

No dependencies. Go 1.22 or later, standard library only.

## Use

```
tiptoe assess  manglillo.example.edu      # passive intel, then paced active probing
tiptoe passive manglillo.example.edu      # passive intel only — zero packets to the host
tiptoe assess  10.0.0.1 --ports 8000,8888 # probe a specific port set
tiptoe assess  host --json                # machine-readable output for the chain
```

An IP address is the only required argument. By default the active phase
probes the ports passive intel turned up, so for an IP that Shodan has
indexed, `tiptoe assess <ip>` is fully automatic. For an IP with no Shodan
record, pass `--ports`.

`--timeout` takes a duration with a unit (`8s`, `1m`), not a bare number.

## What it needs, and what to expect

- **Shodan API key** at `~/.shodan/api_key` — the passive phase reads
  Shodan's cached host record, which is also where the default port list
  comes from. Without it, pass `--ports` explicitly.
- **It is slow on purpose.** The congestion-control pacer waits 8–120
  seconds between probes, so a host with several ports can take minutes.
  The live status line shows a countdown so the wait reads as progress.
  For a quick first run, name two or three ports with `--ports`.

## Where it fits a recon toolchain

Population scanners (aimap, menlohunt, JAXEN-class tools) are loud and fast
across thousands of hosts. tiptoe is the opposite end of that spectrum: the
single monitored host you do not want to spook, or re-probing a host an
aggressive scan already got the source filtered from. Its `--json` output
is shaped for ledger ingest, so it slots in after discovery as a quiet
verification stage.

## Output

The human report has four parts:

- **passive intel** — what was learned without touching the host.
- **active probes** — each port, the service identified, and whether it is
  authenticated. Every active finding is verified, not guessed from a port
  number.
- **pacer trace** — the congestion controller's per-probe decisions.
- **noise** — a budget readout. tiptoe counts its own connections and reports
  the peak rate against a portscan-detection estimate, so loudness is a number
  you can see rather than a thing you hope about.

`--json` emits the whole assessment for `visorlog ingest` or any other stage of
the chain.

## Where tiptoe sits in the chain

| Tool | Built for |
|---|---|
| aimap, menlohunt | population sweeps — thousands of hosts, load distributed |
| **tiptoe** | the single monitored host — quiet, paced, block-aware |

Use the loud tools to find the population. Use tiptoe on the host that would
notice.

---

Built by [NuClide Research](https://nuclide-research.com).
