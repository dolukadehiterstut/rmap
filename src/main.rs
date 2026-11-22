use clap::Parser;
use futures::{stream, StreamExt};
use ipnet::IpNet;
use rand::seq::SliceRandom;
use serde::Serialize;
use std::{
    collections::{BTreeMap, HashMap},
    io::ErrorKind,
    net::{IpAddr, SocketAddr},
    sync::Arc,
    time::{Duration, Instant},
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{lookup_host, TcpStream},
    time::timeout,
};

/// Most commonly used ports (roughly ordered by frequency)
const TOP_PORTS: [u16; 50] = [
    80, 443, 22, 21, 25, 53, 110, 111, 135, 139, 143, 445, 993, 995, 1723, 3306, 3389, 5900,
    8080, 8443, 23, 8000, 8888, 5432, 6379, 27017, 9200, 11211, 5000, 3000, 1433, 1521, 2049,
    5060, 5985, 5984, 6443, 9000, 9090, 10000, 8081, 8008, 49152, 161, 389, 636, 873, 2375,
    2376, 4444,
];

#[derive(Parser)]
#[command(name = "rmap", version, about = "Fast async TCP port scanner")]
struct Args {
    /// Targets: IP, hostname or CIDR (e.g. 192.168.1.0/24)
    #[arg(required = true)]
    targets: Vec<String>,
    /// Ports: "80", "20-100" or "22,80,443,8000-8100" (default: the 1000 most common ports, like nmap)
    #[arg(short, long)]
    ports: Option<String>,
    /// Scan the N most common ports (default 1000; uses nmap's frequency data when installed)
    #[arg(long)]
    top: Option<usize>,
    /// Scan all 65535 ports
    #[arg(short = 'a', long)]
    all: bool,
    /// Number of simultaneous connections
    #[arg(short, long, default_value_t = 500)]
    concurrency: usize,
    /// Connect timeout in ms (default: auto, measured from the target RTT)
    #[arg(short, long)]
    timeout_ms: Option<u64>,
    /// Retries for filtered (timed-out) ports
    #[arg(short, long, default_value_t = 0)]
    retries: u32,
    /// Banner grabbing / simple HTTP probe
    #[arg(short = 'b', long)]
    banner: bool,
    /// Run host discovery first and skip hosts that do not respond
    #[arg(long)]
    ping: bool,
    /// Output results as JSON
    #[arg(long)]
    json: bool,
    /// Disable randomized scan order
    #[arg(long)]
    no_shuffle: bool,
    /// Disable the automatic slower rescan of filtered ports
    #[arg(long)]
    no_rescan: bool,
    /// Max number of adaptive rescan rounds for filtered ports (each round is slower)
    #[arg(long, default_value_t = 3)]
    rescan_rounds: u32,
    /// Limit probes per second
    #[arg(long)]
    max_rate: Option<u64>,
}

#[derive(Clone, Copy, PartialEq)]
enum State {
    Open,
    Closed,
    Filtered,
}

struct Cfg {
    dur: Duration,
    retries: u32,
    banner: bool,
}

#[derive(Serialize)]
struct PortOut {
    port: u16,
    state: &'static str,
    service: &'static str,
    banner: Option<String>,
}

#[derive(Serialize)]
struct HostOut {
    ip: String,
    open: Vec<PortOut>,
    closed: usize,
    filtered: usize,
    filtered_ports: Vec<u16>,
}

#[derive(Serialize)]
struct Report {
    hosts_scanned: usize,
    ports_per_host: usize,
    duration_ms: u128,
    hosts: Vec<HostOut>,
}

fn parse_ports(s: &str) -> Result<Vec<u16>, String> {
    let mut out = Vec::new();
    for part in s.split(',') {
        let part = part.trim();
        let bad = || format!("invalid port expression: {part}");
        if let Some((a, b)) = part.split_once('-') {
            let a: u16 = a.parse().map_err(|_| bad())?;
            let b: u16 = b.parse().map_err(|_| bad())?;
            if a > b {
                return Err(bad());
            }
            out.extend(a..=b);
        } else {
            out.push(part.parse().map_err(|_| bad())?);
        }
    }
    out.sort_unstable();
    out.dedup();
    Ok(out)
}

/// Exact "top N" ports from nmap's own frequency table, if nmap is installed.
fn load_nmap_top(n: usize) -> Option<Vec<u16>> {
    let text = [
        "/usr/share/nmap/nmap-services",
        "/usr/local/share/nmap/nmap-services",
        "/opt/homebrew/share/nmap/nmap-services",
        r"C:\Program Files (x86)\Nmap\nmap-services",
        r"C:\Program Files\Nmap\nmap-services",
    ]
    .iter()
    .find_map(|p| std::fs::read_to_string(p).ok())?;

    let mut v: Vec<(f64, u16)> = Vec::new();
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let mut it = line.split_whitespace();
        let _name = it.next();
        let (Some(pp), Some(fr)) = (it.next(), it.next()) else { continue };
        let Some((port, proto)) = pp.split_once('/') else { continue };
        if proto != "tcp" {
            continue;
        }
        let (Ok(port), Ok(freq)) = (port.parse::<u16>(), fr.parse::<f64>()) else { continue };
        v.push((freq, port));
    }
    v.sort_by(|a, b| b.0.partial_cmp(&a.0).unwrap_or(std::cmp::Ordering::Equal));
    let mut seen = std::collections::HashSet::new();
    let ports: Vec<u16> = v
        .into_iter()
        .filter(|(_, p)| seen.insert(*p))
        .map(|(_, p)| p)
        .take(n)
        .collect();
    if ports.is_empty() { None } else { Some(ports) }
}

/// Fallback approximation: well-known hot ports first, then the lowest port numbers.
fn builtin_top(n: usize) -> Vec<u16> {
    let mut out: Vec<u16> = TOP_PORTS.to_vec();
    let mut p: u32 = 1;
    while out.len() < n && p <= 65535 {
        let port = p as u16;
        if !out.contains(&port) {
            out.push(port);
        }
        p += 1;
    }
    out.truncate(n);
    out
}

fn top_ports(n: usize, quiet: bool) -> Vec<u16> {
    let n = n.clamp(1, 65535);
    if let Some(v) = load_nmap_top(n) {
        return v;
    }
    if !quiet {
        eprintln!(
            "note: nmap-services not found, using a built-in approximation of the top {n} ports \
             (install nmap to use its exact list)"
        );
    }
    builtin_top(n)
}

fn service_name(port: u16) -> &'static str {
    match port {
        21 => "ftp",
        22 => "ssh",
        23 => "telnet",
        25 => "smtp",
        53 => "dns",
        80 => "http",
        110 => "pop3",
        111 => "rpcbind",
        135 => "msrpc",
        139 => "netbios-ssn",
        143 => "imap",
        161 => "snmp",
        389 => "ldap",
        443 => "https",
        445 => "smb",
        636 => "ldaps",
        993 => "imaps",
        995 => "pop3s",
        1433 => "mssql",
        1521 => "oracle",
        2375 | 2376 => "docker",
        3306 => "mysql",
        3389 => "rdp",
        5060 => "sip",
        5432 => "postgresql",
        5900 => "vnc",
        6379 => "redis",
        8080 | 8000 | 8008 | 8081 | 8888 => "http-alt",
        8443 => "https-alt",
        9200 => "elasticsearch",
        9929 => "nping-echo",
        11211 => "memcached",
        27017 => "mongodb",
        _ => "unknown",
    }
}

async fn resolve(target: &str) -> Vec<IpAddr> {
    if let Ok(net) = target.parse::<IpNet>() {
        return net.hosts().collect();
    }
    if let Ok(ip) = target.parse::<IpAddr>() {
        return vec![ip];
    }
    match lookup_host((target, 0)).await {
        Ok(mut addrs) => addrs.next().map(|a| vec![a.ip()]).unwrap_or_default(),
        Err(_) => Vec::new(),
    }
}

/// Is the host up? If the connection is accepted OR refused (RST), the host is alive.
async fn host_alive(ip: IpAddr, dur: Duration) -> bool {
    let probes = [80u16, 443, 22, 445, 3389].map(|p| async move {
        match timeout(dur, TcpStream::connect(SocketAddr::new(ip, p))).await {
            Ok(Ok(_)) => true,
            Ok(Err(e)) => e.kind() == ErrorKind::ConnectionRefused,
            Err(_) => false,
        }
    });
    futures::future::join_all(probes).await.into_iter().any(|x| x)
}

/// Estimate the round-trip time: an accepted or refused connection takes about one RTT.
async fn measure_rtt(ip: IpAddr) -> Option<Duration> {
    let probes = [80u16, 443, 22, 53].map(|p| async move {
        let t = Instant::now();
        match timeout(Duration::from_millis(2000), TcpStream::connect(SocketAddr::new(ip, p))).await {
            Ok(Ok(_)) => Some(t.elapsed()),
            Ok(Err(e)) if e.kind() == ErrorKind::ConnectionRefused => Some(t.elapsed()),
            _ => None,
        }
    });
    futures::future::join_all(probes).await.into_iter().flatten().min()
}

async fn grab_banner(s: &mut TcpStream, port: u16) -> Option<String> {
    let mut buf = [0u8; 512];
    let mut n = match timeout(Duration::from_millis(300), s.read(&mut buf)).await {
        Ok(Ok(n)) => n,
        _ => 0,
    };
    if n == 0 && matches!(port, 80 | 8000 | 8008 | 8080 | 8081 | 8888) {
        s.write_all(b"HEAD / HTTP/1.0\r\n\r\n").await.ok()?;
        n = match timeout(Duration::from_millis(500), s.read(&mut buf)).await {
            Ok(Ok(n)) => n,
            _ => 0,
        };
    }
    if n == 0 {
        return None;
    }
    let text = String::from_utf8_lossy(&buf[..n]).into_owned();
    let line = text
        .lines()
        .find(|l| l.to_ascii_lowercase().starts_with("server:"))
        .or_else(|| text.lines().next())?;
    Some(line.trim().chars().take(80).collect())
}

async fn scan_port(ip: IpAddr, port: u16, cfg: Arc<Cfg>) -> (IpAddr, u16, State, Option<String>) {
    let addr = SocketAddr::new(ip, port);
    for _ in 0..=cfg.retries {
        match timeout(cfg.dur, TcpStream::connect(addr)).await {
            Ok(Ok(mut s)) => {
                let _ = s.set_nodelay(true);
                let b = if cfg.banner { grab_banner(&mut s, port).await } else { None };
                return (ip, port, State::Open, b);
            }
            // RST received: port is closed, no need to retry
            Ok(Err(e)) if e.kind() == ErrorKind::ConnectionRefused => {
                return (ip, port, State::Closed, None)
            }
            // Timeout or other error: treat as filtered and retry
            _ => continue,
        }
    }
    (ip, port, State::Filtered, None)
}

type ProbeResult = (IpAddr, u16, State, Option<String>);

fn fmt_dur(d: Duration) -> String {
    let s = d.as_secs_f64();
    if s >= 60.0 {
        format!("{}m {:02}s", (s / 60.0) as u64, (s % 60.0) as u64)
    } else {
        format!("{s:.1}s")
    }
}

/// Run one scan pass over `tasks` with at most `conc` probes in flight,
/// optionally paced to `rate` probes per second.
async fn run_pass(
    tasks: Vec<(IpAddr, u16)>,
    conc: usize,
    cfg: Arc<Cfg>,
    label: &str,
    rate: Option<u64>,
    quiet: bool,
) -> Vec<ProbeResult> {
    let total = tasks.len();
    let t0 = Instant::now();
    let tstart = tokio::time::Instant::now();
    let rate = rate.map(|r| r.max(1) as f64);
    let mut results = Box::pin(
        stream::iter(tasks)
            .enumerate()
            .then(move |(i, t)| async move {
                if let Some(r) = rate {
                    tokio::time::sleep_until(tstart + Duration::from_secs_f64(i as f64 / r)).await;
                }
                t
            })
            .map(move |(ip, p)| scan_port(ip, p, cfg.clone()))
            .buffer_unordered(conc.max(1)),
    );
    let mut out = Vec::with_capacity(total);
    while let Some(r) = results.next().await {
        out.push(r);
        if !quiet && out.len() % 2000 == 0 {
            let done = out.len();
            let eta = t0.elapsed().as_secs_f64() / done as f64 * (total - done) as f64;
            eprint!(
                "\r[{label} {done}/{total} | {} elapsed | ETA {}]   ",
                fmt_dur(t0.elapsed()),
                fmt_dur(Duration::from_secs_f64(eta))
            );
        }
    }
    out
}

#[derive(Default)]
struct HostAcc {
    open: Vec<PortOut>,
    closed: usize,
    filtered: usize,
    filtered_ports: Vec<u16>,
}

#[tokio::main]
async fn main() {
    let args = Args::parse();

    // Raise the file-descriptor limit (required for high concurrency)
    #[allow(unused_mut)]
    let mut max_conc = args.concurrency.max(1);
    #[cfg(unix)]
    {
        if let Ok(limit) = rlimit::increase_nofile_limit(1 << 16) {
            max_conc = max_conc.min((limit as usize).saturating_sub(64).max(1));
        }
    }

    // Port selection: --all > --top > -p > default (top 1000, like nmap)
    let ports: Vec<u16> = if args.all {
        (1..=65535u16).collect()
    } else if let Some(n) = args.top {
        top_ports(n, args.json)
    } else if let Some(p) = &args.ports {
        parse_ports(p).unwrap_or_else(|e| {
            eprintln!("{e}");
            std::process::exit(1)
        })
    } else {
        top_ports(1000, args.json)
    };

    // Resolve targets
    let mut ips: Vec<IpAddr> = Vec::new();
    for t in &args.targets {
        let r = resolve(t).await;
        if r.is_empty() {
            eprintln!("warning: could not resolve target: {t}");
        }
        ips.extend(r);
    }
    ips.sort_unstable();
    ips.dedup();
    if ips.is_empty() {
        eprintln!("no hosts to scan");
        std::process::exit(1);
    }

    let start = Instant::now();
    let dur = match args.timeout_ms {
        Some(ms) => Duration::from_millis(ms),
        None => {
            let mut rtt: Option<Duration> = None;
            for &ip in ips.iter().take(3) {
                if let Some(r) = measure_rtt(ip).await {
                    rtt = Some(rtt.map_or(r, |x| x.max(r)));
                }
            }
            let auto = match rtt {
                Some(r) => (r * 3).clamp(Duration::from_millis(300), Duration::from_millis(2000)),
                None => Duration::from_millis(1000),
            };
            if !args.json {
                let shown = rtt.map(|r| format!("{r:.0?}")).unwrap_or_else(|| "n/a".to_string());
                eprintln!("measured RTT: {shown}, using timeout {auto:.0?}");
            }
            auto
        }
    };

    // Host discovery
    if args.ping {
        let before = ips.len();
        ips = stream::iter(ips)
            .map(|ip| async move { (ip, host_alive(ip, dur).await) })
            .buffer_unordered(max_conc.min(512))
            .filter_map(|(ip, up)| async move { up.then_some(ip) })
            .collect()
            .await;
        ips.sort_unstable();
        if !args.json {
            eprintln!("host discovery: {}/{} hosts up", ips.len(), before);
        }
    }

    // Build (ip, port) pairs and shuffle them: avoids hammering one host in sequence
    // and reduces the chance of tripping rate limits / IDS
    let mut tasks: Vec<(IpAddr, u16)> = Vec::with_capacity(ips.len() * ports.len());
    for &ip in &ips {
        for &p in &ports {
            tasks.push((ip, p));
        }
    }
    if !args.no_shuffle {
        tasks.shuffle(&mut rand::thread_rng());
    }
    let total = tasks.len();

    if !args.json {
        eprintln!(
            "rmap: {} hosts x {} ports = {} probes, concurrency {}",
            ips.len(),
            ports.len(),
            total,
            max_conc
        );
    }

    let cfg = Arc::new(Cfg { dur, retries: args.retries, banner: args.banner });
    let mut phases: Vec<(String, Duration)> = Vec::new();
    let t0 = Instant::now();
    let mut all =
        run_pass(tasks, max_conc, cfg, "scan", args.max_rate, args.json).await;
    phases.push(("scan".to_string(), t0.elapsed()));

    // Adaptive rescan rounds. Fast scans over the internet lose packets or hit rate limits,
    // which makes open/closed ports look "filtered". Each round retries only the filtered
    // ports with lower concurrency and a longer timeout, and stops once it stops helping.
    let rounds = if args.no_rescan { 0 } else { args.rescan_rounds };
    let (mut r_conc, mut r_dur) = (max_conc, dur);
    for round in 1..=rounds {
        let retry: Vec<(IpAddr, u16)> = all
            .iter()
            .filter(|r| r.2 == State::Filtered)
            .map(|r| (r.0, r.1))
            .collect();
        if retry.is_empty() {
            break;
        }
        r_conc = (r_conc / 2).max(20);
        r_dur = (r_dur * 3 / 2).min(Duration::from_secs(5));
        let est = r_dur.as_secs_f64() * retry.len() as f64 / r_conc as f64;
        if est > 600.0 {
            if !args.json {
                eprintln!(
                    "\rnote: {} filtered ports, rescan would take ~{}; skipping (host may be firewalled)",
                    retry.len(),
                    fmt_dur(Duration::from_secs_f64(est))
                );
            }
            break;
        }
        if !args.json {
            eprintln!(
                "\rrescan {round}/{rounds}: {} filtered ports, concurrency {r_conc}, timeout {:.0?}",
                retry.len(),
                r_dur
            );
        }
        let before = retry.len();
        let t = Instant::now();
        let cfg_r = Arc::new(Cfg { dur: r_dur, retries: 0, banner: args.banner });
        let second = run_pass(retry, r_conc, cfg_r, "rescan", None, args.json).await;
        phases.push((format!("rescan {round}"), t.elapsed()));
        let map: HashMap<(IpAddr, u16), (State, Option<String>)> =
            second.into_iter().map(|(ip, p, s, b)| ((ip, p), (s, b))).collect();
        for r in all.iter_mut() {
            if r.2 == State::Filtered {
                if let Some((st, b)) = map.get(&(r.0, r.1)) {
                    r.2 = *st;
                    r.3 = b.clone();
                }
            }
        }
        let after = all.iter().filter(|r| r.2 == State::Filtered).count();
        // Stop when a round resolves less than 1% of the remaining filtered ports
        if after * 100 >= before * 99 {
            break;
        }
    }
    let filtered_final = all.iter().filter(|r| r.2 == State::Filtered).count();
    if !args.json && total > 0 && filtered_final * 2 > total {
        eprintln!(
            "warning: more than half of all probes were filtered, results may be unreliable.\n         Try lower concurrency and a longer timeout, e.g. -c 200 -t 2000"
        );
    }

    let mut hosts: BTreeMap<IpAddr, HostAcc> =
        ips.iter().map(|&ip| (ip, HostAcc::default())).collect();
    for (ip, port, state, banner) in all {
        let acc = hosts.entry(ip).or_default();
        match state {
            State::Open => acc.open.push(PortOut {
                port,
                state: "open",
                service: service_name(port),
                banner,
            }),
            State::Closed => acc.closed += 1,
            State::Filtered => {
                acc.filtered += 1;
                acc.filtered_ports.push(port);
            }
        }
    }
    if !args.json {
        eprint!("\r{:<30}\r", "");
    }

    let elapsed = start.elapsed();
    let mut out_hosts: Vec<HostOut> = Vec::new();
    for (ip, mut acc) in hosts {
        acc.open.sort_by_key(|p| p.port);
        acc.filtered_ports.sort_unstable();
        // Without --ping, skip hosts with nothing to report to keep output short
        if !args.ping && acc.open.is_empty() && acc.closed == 0 {
            continue;
        }
        out_hosts.push(HostOut {
            ip: ip.to_string(),
            open: acc.open,
            closed: acc.closed,
            filtered: acc.filtered,
            filtered_ports: acc.filtered_ports,
        });
    }

    if args.json {
        let report = Report {
            hosts_scanned: ips.len(),
            ports_per_host: ports.len(),
            duration_ms: elapsed.as_millis(),
            hosts: out_hosts,
        };
        println!("{}", serde_json::to_string_pretty(&report).unwrap());
        return;
    }

    let mut total_open = 0;
    for h in &out_hosts {
        println!("\nHost: {}  ({} closed, {} filtered)", h.ip, h.closed, h.filtered);
        // nmap-style: list filtered ports only when there are few of them
        let mut rows: Vec<(u16, &str, &str, &str)> = h
            .open
            .iter()
            .map(|p| (p.port, p.state, p.service, p.banner.as_deref().unwrap_or("")))
            .collect();
        if h.filtered <= 25 {
            rows.extend(h.filtered_ports.iter().map(|&p| (p, "filtered", service_name(p), "")));
        }
        rows.sort_by_key(|r| r.0);
        if rows.is_empty() {
            println!("  no open ports");
            continue;
        }
        println!("  {:<10}{:<10}{:<16}BANNER", "PORT", "STATE", "SERVICE");
        for (port, state, service, banner) in rows {
            if state == "open" {
                total_open += 1;
            }
            println!("  {:<10}{:<10}{:<16}{}", format!("{port}/tcp"), state, service, banner);
        }
    }
    let rate = total as f64 / phases[0].1.as_secs_f64().max(0.001);
    println!("\n{} hosts, {} open ports", ips.len(), total_open);
    println!("Total time: {} (first pass {:.0} probes/s)", fmt_dur(elapsed), rate);
    let breakdown: Vec<String> = phases.iter().map(|(n, d)| format!("{n} {}", fmt_dur(*d))).collect();
    println!("Phases: {}", breakdown.join(", "));
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_single_port() {
        assert_eq!(parse_ports("80").unwrap(), vec![80]);
    }

    #[test]
    fn parses_ranges_and_lists() {
        assert_eq!(parse_ports("22,80,100-102").unwrap(), vec![22, 80, 100, 101, 102]);
    }

    #[test]
    fn dedups_and_sorts() {
        assert_eq!(parse_ports("443,80,80,79-81").unwrap(), vec![79, 80, 81, 443]);
    }

    #[test]
    fn rejects_invalid_input() {
        assert!(parse_ports("abc").is_err());
        assert!(parse_ports("100-50").is_err());
        assert!(parse_ports("70000").is_err());
    }

    #[test]
    fn known_services() {
        assert_eq!(service_name(22), "ssh");
        assert_eq!(service_name(65000), "unknown");
    }

    #[test]
    fn builtin_top_has_requested_size_and_no_duplicates() {
        let v = builtin_top(1000);
        assert_eq!(v.len(), 1000);
        let mut d = v.clone();
        d.sort_unstable();
        d.dedup();
        assert_eq!(d.len(), 1000);
    }

    #[tokio::test]
    async fn resolves_cidr_hosts() {
        let ips = resolve("192.168.1.0/30").await;
        assert_eq!(ips.len(), 2);
    }

    #[tokio::test]
    async fn detects_open_and_closed_port() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let open_port = listener.local_addr().unwrap().port();
        let cfg = Arc::new(Cfg { dur: Duration::from_millis(500), retries: 0, banner: false });
        let ip: IpAddr = "127.0.0.1".parse().unwrap();

        let (_, _, state, _) = scan_port(ip, open_port, cfg.clone()).await;
        assert!(state == State::Open);

        drop(listener);
        let (_, _, state, _) = scan_port(ip, open_port, cfg).await;
        assert!(state == State::Closed);
    }
}