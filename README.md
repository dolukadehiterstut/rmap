# rmap

[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
![Rust](https://img.shields.io/badge/rust-stable-orange.svg)

A fast, asynchronous TCP port scanner written in Rust, inspired by [nmap](https://nmap.org).
Built on `tokio` for high-concurrency connect scanning, with CIDR support, host discovery,
banner grabbing and JSON output.

> **Legal notice:** use `rmap` only on systems you own or are explicitly authorized to test.
> See [SECURITY.md](SECURITY.MD).

## Features

- Async TCP connect scan with configurable concurrency (default 500)
- Targets: single IP, hostname, multiple targets, CIDR ranges (`192.168.1.0/24`)
- Host discovery (`--ping`): a host counts as alive if it accepts **or** actively refuses (RST) a TCP probe
- Port specs: `80`, `20-100`, `22,80,443,8000-8100`, or `--top N` for the most common ports
- Smart retries: only timed-out (filtered) ports are retried; RST (closed) returns immediately
- Randomized scan order to spread load and reduce rate-limit / IDS triggers
- Banner grabbing with a lightweight HTTP `HEAD` probe
- Machine-readable `--json` output
- Automatically raises the file-descriptor limit on Unix

## Install

```bash
git clone https://github.com/dolukadehiterstut/rmap.git
cd rmap
cargo build --release
# binary: ./target/release/rmap
```

## Usage

```bash
# Scan the 20 most common ports on a host with banner grabbing
rmap scanme.nmap.org --top 20 -b

# Discover live hosts in a subnet, then scan them
rmap 192.168.1.0/24 --ping --top 50

# Full port range, high concurrency, JSON output
rmap 10.0.0.5 -p 1-65535 -c 5000 --json > scan.json
```

```
Usage: rmap [OPTIONS] <TARGETS>...

Options:
  -p, --ports <PORTS>          Ports: "80", "20-100", "22,80,443" (default: top 1000, like nmap)
      --top <N>                Scan the N most common ports (default 1000)
      -a, --all                Scan all 65535 ports
  -c, --concurrency <N>        Simultaneous connections [default: 500]
  -t, --timeout-ms <MS>        Connect timeout in ms [default: auto from RTT]
  -r, --retries <N>            First-pass retries for filtered ports [default: 0]
      --no-rescan              Disable the automatic slower rescan of filtered ports
      --rescan-rounds <N>      Max adaptive rescan rounds [default: 3]
      --max-rate <N>           Limit first pass to N probes/second
  -b, --banner                 Banner grabbing / HTTP probe
      --ping                   Host discovery before scanning
      --json                   JSON output
      --no-shuffle             Disable randomized scan order
```

### Example output

```
Host: 192.168.1.10  (1021 closed, 0 filtered)
  PORT      STATE   SERVICE          BANNER
  22/tcp    open    ssh             SSH-2.0-OpenSSH_9.6
  80/tcp    open    http-alt        Server: nginx
```

<!-- TODO: replace with a real terminal screenshot or asciinema recording -->

## How it works

`rmap` builds a list of `(ip, port)` pairs, shuffles it, and drives it through a bounded
`buffer_unordered` stream so that at most *N* connections are in flight. Each probe is
classified as **open** (handshake completes), **closed** (RST / connection refused) or
**filtered** (timeout after retries).

## Benchmarks

Loopback comparison on this machine, with a temporary TCP listener on port 8080.
Both tools scanned their 1,000 most common TCP ports; Nmap was explicitly run in
connect mode (`-sT`) to match rmap. Times are medians of three runs and include
process startup.

| Tool | Target | Ports | Median time | Result |
|------|--------|-------|-------------|--------|
| rmap (default) | 127.0.0.1 | top 1000 TCP | 0.059 s | 1 open, 999 closed, 0 filtered |
| nmap `-sT --top-ports 1000` | 127.0.0.1 | top 1000 TCP | 0.092 s | 1 open, 999 closed, 0 filtered |

Both identified `8080/tcp` as open; rmap was 1.55x faster in this local test.
This result measures loopback performance, not performance or accuracy on remote networks.

## Roadmap

- [ ] UDP scanning
- [ ] Service/version detection with a probe database
- [ ] OS fingerprinting heuristics
- [ ] IPv6 improvements, XML output

## Development

```bash
cargo test
cargo fmt --all
cargo clippy --all-targets
```

## License

MIT, see [LICENSE](LICENSE).
