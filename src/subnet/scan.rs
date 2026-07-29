use super::watch::perform_subnet_watch;
use super::{Ipv4Subnet, Ipv6Subnet};
use crate::colors::Colorize;
use crate::icmp::ping_host_once;
use crate::output::{color_time, micros_to_ms, print_statistics, print_with_prefix};
use crate::tcp::tcp_connect_once;
use crate::udp::{ProbeOutcome, udp_probe_once};
use std::collections::{HashSet, VecDeque};
use std::fmt::Write as _;
use std::net::{IpAddr, SocketAddr};
use std::thread;
use std::time::Duration;

const DEFAULT_SUBNET_BATCH: usize = 32;

pub(super) enum ProbeKind {
    Tcp {
        port: u16,
        timeout_ms: u64,
    },
    Udp {
        port: u16,
        timeout: Duration,
    },
    Icmp {
        timeout: Duration,
        ttl: u8,
        ident: u16,
        payload: [u8; 24],
    },
}

impl ProbeKind {
    const fn proto_label(&self) -> &'static str {
        match self {
            Self::Tcp { .. } => "TCP subnet",
            Self::Udp { .. } => "UDP subnet",
            Self::Icmp { .. } => "ICMP subnet",
        }
    }

    pub(super) const fn header_protocol(&self) -> &'static str {
        match self {
            Self::Tcp { .. } => "TCP",
            Self::Udp { .. } => "UDP",
            Self::Icmp { .. } => "ICMP",
        }
    }

    pub(super) const fn header_port(&self) -> Option<u16> {
        match self {
            Self::Tcp { port, .. } | Self::Udp { port, .. } => Some(*port),
            Self::Icmp { .. } => None,
        }
    }
}

#[derive(Clone, Copy)]
enum ScanVerdict {
    Open { rtt_us: u128 },
    Down,
    UdpClosed,
    UdpNoResponse,
}

#[derive(Clone, Copy)]
pub(super) struct ScanResult {
    pub(super) host: IpAddr,
    verdict: ScanVerdict,
}

impl ScanResult {
    const fn latency_us(&self) -> Option<u128> {
        match self.verdict {
            ScanVerdict::Open { rtt_us } => Some(rtt_us),
            _ => None,
        }
    }

    pub(super) const fn is_responsive(&self) -> bool {
        matches!(self.verdict, ScanVerdict::Open { .. })
    }

    pub(super) fn format(&self, minimal: bool) -> String {
        match self.verdict {
            ScanVerdict::Open { rtt_us } => {
                let colored_ip = self.host.to_string().green();
                if minimal {
                    colored_ip
                } else {
                    format!("{} {}", colored_ip, color_time(micros_to_ms(rtt_us)))
                }
            }
            ScanVerdict::Down => self.host.to_string().red(),
            ScanVerdict::UdpClosed => format!("{} closed", self.host.to_string().red()),
            ScanVerdict::UdpNoResponse => {
                format!("{} open|filtered", self.host.to_string().orange())
            }
        }
    }
}

fn print_chunk_row(results: &[ScanResult], minimal: bool, attempt_idx: usize, attempts: usize) {
    if results.is_empty() {
        return;
    }

    let entries = results
        .iter()
        .map(|status| status.format(minimal))
        .collect::<Vec<_>>()
        .join(", ");

    let mut line = format!("[{entries}]");
    if attempts > 1 {
        line = format!("Attempt {attempt_idx}/{attempts} {line}");
    }

    print_with_prefix(minimal, &line);
}

pub(super) fn probe_chunk(hosts: &[IpAddr], kind: &ProbeKind, seq: &mut u16) -> Vec<ScanResult> {
    let mut handles = Vec::with_capacity(hosts.len());
    for &host in hosts {
        let verdict = match *kind {
            ProbeKind::Tcp { port, timeout_ms } => thread::spawn(move || {
                tcp_connect_once(host, port, timeout_ms).map_or(ScanVerdict::Down, |latency| {
                    ScanVerdict::Open {
                        rtt_us: latency.as_micros(),
                    }
                })
            }),
            ProbeKind::Udp { port, timeout } => {
                let payload = crate::udp::probe_payload(port);
                thread::spawn(move || {
                    let addr = SocketAddr::new(host, port);
                    match udp_probe_once(addr, &payload, timeout) {
                        ProbeOutcome::Open { rtt, .. } => ScanVerdict::Open {
                            rtt_us: rtt.as_micros(),
                        },
                        ProbeOutcome::Closed => ScanVerdict::UdpClosed,
                        ProbeOutcome::NoResponse => ScanVerdict::UdpNoResponse,
                    }
                })
            }
            ProbeKind::Icmp {
                timeout,
                ttl,
                ident,
                payload,
            } => {
                let current_seq = *seq;
                *seq = seq.wrapping_add(1);
                thread::spawn(move || {
                    match ping_host_once(host, current_seq, timeout, ttl, ident, &payload) {
                        Ok((_bytes, rtt)) => ScanVerdict::Open {
                            rtt_us: rtt.as_micros(),
                        },
                        Err(_) => ScanVerdict::Down,
                    }
                })
            }
        };
        handles.push((host, verdict));
    }

    handles
        .into_iter()
        .map(|(host, handle)| {
            let fallback = match kind {
                ProbeKind::Udp { .. } => ScanVerdict::UdpNoResponse,
                _ => ScanVerdict::Down,
            };
            ScanResult {
                host,
                verdict: handle.join().unwrap_or(fallback),
            }
        })
        .collect()
}

fn ensure_attempts(attempts: usize) -> usize {
    attempts.max(1)
}

pub(super) fn format_scan_header(
    verb: &str,
    protocol: &str,
    subnet_notation: &str,
    host_count: u128,
    port: Option<u16>,
    suffix: Option<&str>,
) -> String {
    let mut message = format!(
        "{verb} {} ({} hosts) via {}",
        subnet_notation.bright_blue(),
        host_count,
        protocol
    );

    if let Some(p) = port {
        write!(&mut message, " port {p}").expect("writing to String should not fail");
    }

    if let Some(s) = suffix {
        write!(&mut message, " {s}").expect("writing to String should not fail");
    }

    message
}

fn print_host_summary(total: usize, responsive: usize, minimal: bool) {
    let summary = format!(
        "Hosts responsive: {}/{}",
        responsive.to_string().green(),
        total
    );
    print_with_prefix(minimal, &summary);
}

pub(super) fn print_responsive_minimal(responsive_hosts: &HashSet<IpAddr>, minimal: bool) {
    let mut responsive_list: Vec<IpAddr> = responsive_hosts.iter().copied().collect();
    responsive_list.sort_by_key(|ip| match ip {
        IpAddr::V4(v4) => (0, u128::from(u32::from(*v4))),
        IpAddr::V6(v6) => (1, u128::from(*v6)),
    });
    if responsive_list.is_empty() {
        return;
    }
    let entries = responsive_list
        .iter()
        .map(|ip| ip.to_string().green())
        .collect::<Vec<_>>()
        .join(", ");
    let message = format!("[{entries}]");
    print_with_prefix(minimal, &message);
}

pub(super) struct ScanConfig {
    pub(super) notation: String,
    pub(super) host_count: u128,
    too_large: bool,
    pub(super) kind: ProbeKind,
    attempts_per_host: usize,
    pub(super) minimal: bool,
    pub(super) watch: bool,
}

fn print_empty_or_too_large(cfg: &ScanConfig, hosts: &[IpAddr]) -> bool {
    if cfg.host_count == 0 {
        let message = format!("{} has no usable host addresses", cfg.notation.yellow());
        print_with_prefix(cfg.minimal, &message);
        return true;
    }
    if cfg.too_large {
        let message = format!(
            "{} has too many addresses to scan (max /112 supported)",
            cfg.notation.yellow()
        );
        print_with_prefix(cfg.minimal, &message);
        return true;
    }
    if hosts.is_empty() {
        let message = format!("{} has no usable host addresses", cfg.notation.yellow());
        print_with_prefix(cfg.minimal, &message);
        return true;
    }
    false
}

fn perform_subnet_scan(hosts: &[IpAddr], cfg: &ScanConfig) {
    if print_empty_or_too_large(cfg, hosts) {
        return;
    }

    if cfg.watch {
        perform_subnet_watch(hosts, cfg);
        return;
    }

    let attempts = ensure_attempts(cfg.attempts_per_host);
    let attempts_suffix = (attempts > 1).then(|| format!("({attempts} attempts/host)"));
    let header = format_scan_header(
        "Scanning",
        cfg.kind.header_protocol(),
        &cfg.notation,
        cfg.host_count,
        cfg.kind.header_port(),
        attempts_suffix.as_deref(),
    );
    print_with_prefix(cfg.minimal, &header);

    let chunk_size = hosts.len().min(DEFAULT_SUBNET_BATCH);
    let mut times = VecDeque::new();
    let mut successes = 0usize;
    let mut responsive_hosts: HashSet<IpAddr> = HashSet::new();
    let mut seq: u16 = 1;

    for attempt_idx in 0..attempts {
        for chunk in hosts.chunks(chunk_size) {
            let results = probe_chunk(chunk, &cfg.kind, &mut seq);
            if !cfg.minimal {
                print_chunk_row(&results, cfg.minimal, attempt_idx + 1, attempts);
            }

            for status in &results {
                if status.is_responsive() {
                    successes += 1;
                    responsive_hosts.insert(status.host);
                    times.push_back(status.latency_us().unwrap_or(0));
                } else {
                    times.push_back(0);
                }
            }
        }
    }

    let total_attempts = hosts.len() * attempts;

    if cfg.minimal {
        print_responsive_minimal(&responsive_hosts, cfg.minimal);
    }

    print_host_summary(hosts.len(), responsive_hosts.len(), cfg.minimal);
    print_statistics(cfg.kind.proto_label(), total_attempts, successes, &times);
}

fn run_v4_subnet_scan(
    subnet: Ipv4Subnet,
    kind: ProbeKind,
    attempts_per_host: usize,
    minimal: bool,
    watch: bool,
) {
    let hosts: Vec<IpAddr> = subnet.iter_hosts().map(IpAddr::V4).collect();
    perform_subnet_scan(
        &hosts,
        &ScanConfig {
            notation: subnet.notation(),
            host_count: subnet.host_count(),
            too_large: false,
            kind,
            attempts_per_host,
            minimal,
            watch,
        },
    );
}

fn run_v6_subnet_scan(
    subnet: &Ipv6Subnet,
    kind: ProbeKind,
    attempts_per_host: usize,
    minimal: bool,
    watch: bool,
) {
    let host_count = subnet.host_count();
    let hosts: Vec<IpAddr> = subnet.iter_hosts().map(IpAddr::V6).collect();
    perform_subnet_scan(
        &hosts,
        &ScanConfig {
            notation: subnet.notation(),
            host_count,
            too_large: host_count == u128::MAX,
            kind,
            attempts_per_host,
            minimal,
            watch,
        },
    );
}

pub fn perform_tcp_subnet_scan(
    subnet: Ipv4Subnet,
    port: u16,
    timeout_ms: u64,
    attempts_per_host: usize,
    minimal: bool,
    watch: bool,
) {
    run_v4_subnet_scan(
        subnet,
        ProbeKind::Tcp { port, timeout_ms },
        attempts_per_host,
        minimal,
        watch,
    );
}

#[allow(clippy::too_many_arguments)]
pub fn perform_icmp_subnet_scan(
    subnet: Ipv4Subnet,
    timeout_ms: u64,
    ttl: u8,
    ident: u16,
    attempts_per_host: usize,
    payload: &[u8; 24],
    minimal: bool,
    watch: bool,
) {
    run_v4_subnet_scan(
        subnet,
        ProbeKind::Icmp {
            timeout: Duration::from_millis(timeout_ms),
            ttl,
            ident,
            payload: *payload,
        },
        attempts_per_host,
        minimal,
        watch,
    );
}

pub fn perform_tcp_ipv6_subnet_scan(
    subnet: &Ipv6Subnet,
    port: u16,
    timeout_ms: u64,
    attempts_per_host: usize,
    minimal: bool,
    watch: bool,
) {
    run_v6_subnet_scan(
        subnet,
        ProbeKind::Tcp { port, timeout_ms },
        attempts_per_host,
        minimal,
        watch,
    );
}

#[allow(clippy::too_many_arguments)]
pub fn perform_icmp_ipv6_subnet_scan(
    subnet: &Ipv6Subnet,
    timeout_ms: u64,
    ttl: u8,
    ident: u16,
    attempts_per_host: usize,
    payload: &[u8; 24],
    minimal: bool,
    watch: bool,
) {
    run_v6_subnet_scan(
        subnet,
        ProbeKind::Icmp {
            timeout: Duration::from_millis(timeout_ms),
            ttl,
            ident,
            payload: *payload,
        },
        attempts_per_host,
        minimal,
        watch,
    );
}

pub fn perform_udp_subnet_scan(
    subnet: Ipv4Subnet,
    port: u16,
    timeout_ms: u64,
    attempts_per_host: usize,
    minimal: bool,
    watch: bool,
) {
    run_v4_subnet_scan(
        subnet,
        ProbeKind::Udp {
            port,
            timeout: Duration::from_millis(timeout_ms),
        },
        attempts_per_host,
        minimal,
        watch,
    );
}

pub fn perform_udp_ipv6_subnet_scan(
    subnet: &Ipv6Subnet,
    port: u16,
    timeout_ms: u64,
    attempts_per_host: usize,
    minimal: bool,
    watch: bool,
) {
    run_v6_subnet_scan(
        subnet,
        ProbeKind::Udp {
            port,
            timeout: Duration::from_millis(timeout_ms),
        },
        attempts_per_host,
        minimal,
        watch,
    );
}
