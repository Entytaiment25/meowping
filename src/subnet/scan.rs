use super::watch::perform_subnet_watch;
use super::{Ipv4Subnet, Ipv6Subnet};
use crate::colors::Colorize;
use crate::icmp::ping_host_once;
use crate::output::{color_time, micros, print_with_prefix};
use crate::tcp::tcp_connect_once;
use crate::udp::{ProbeOutcome, udp_probe_once};
use std::fmt::Write as _;
use std::net::{IpAddr, SocketAddr};
use std::thread;
use std::time::Duration;

#[derive(Clone, Copy)]
pub enum ProbeKind {
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
    pub const fn tcp(port: u16, timeout_ms: u64) -> Self {
        Self::Tcp { port, timeout_ms }
    }

    pub const fn udp(port: u16, timeout_ms: u64) -> Self {
        Self::Udp {
            port,
            timeout: Duration::from_millis(timeout_ms),
        }
    }

    pub const fn icmp(timeout_ms: u64, ttl: u8, ident: u16, payload: [u8; 24]) -> Self {
        Self::Icmp {
            timeout: Duration::from_millis(timeout_ms),
            ttl,
            ident,
            payload,
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
    Open { rtt_us: u64 },
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
    pub(super) const fn latency_us(&self) -> Option<u64> {
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
                    format!("{} {}", colored_ip, color_time(rtt_us))
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

const MAX_CONCURRENT_PROBES: usize = 512;

pub(super) fn probe_chunk(hosts: &[IpAddr], kind: &ProbeKind, seq: &mut u16) -> Vec<ScanResult> {
    let mut results = Vec::with_capacity(hosts.len());
    for batch in hosts.chunks(MAX_CONCURRENT_PROBES) {
        results.extend(probe_batch(batch, kind, seq));
    }
    results
}

fn probe_once(host: IpAddr, kind: ProbeKind, seq: u16) -> ScanVerdict {
    match kind {
        ProbeKind::Tcp { port, timeout_ms } => {
            tcp_connect_once(host, port, timeout_ms).map_or(ScanVerdict::Down, |latency| {
                ScanVerdict::Open {
                    rtt_us: micros(latency),
                }
            })
        }
        ProbeKind::Udp { port, timeout } => {
            let payload = crate::udp::probe_payload(port);
            match udp_probe_once(SocketAddr::new(host, port), &payload, timeout) {
                ProbeOutcome::Open { rtt, .. } => ScanVerdict::Open {
                    rtt_us: micros(rtt),
                },
                ProbeOutcome::Closed => ScanVerdict::UdpClosed,
                ProbeOutcome::NoResponse => ScanVerdict::UdpNoResponse,
            }
        }
        ProbeKind::Icmp {
            timeout,
            ttl,
            ident,
            payload,
        } => match ping_host_once(host, seq, timeout, ttl, ident, &payload) {
            Ok((_bytes, rtt)) => ScanVerdict::Open {
                rtt_us: micros(rtt),
            },
            Err(_) => ScanVerdict::Down,
        },
    }
}

fn probe_batch(hosts: &[IpAddr], kind: &ProbeKind, seq: &mut u16) -> Vec<ScanResult> {
    let kind = *kind;
    let fallback = match kind {
        ProbeKind::Udp { .. } => ScanVerdict::UdpNoResponse,
        _ => ScanVerdict::Down,
    };
    let mut handles = Vec::with_capacity(hosts.len());
    for &host in hosts {
        let current_seq = *seq;
        if matches!(kind, ProbeKind::Icmp { .. }) {
            *seq = seq.wrapping_add(1);
        }
        handles.push((
            host,
            thread::spawn(move || probe_once(host, kind, current_seq)),
        ));
    }

    handles
        .into_iter()
        .map(|(host, handle)| ScanResult {
            host,
            verdict: handle.join().unwrap_or(fallback),
        })
        .collect()
}

pub(super) fn ensure_rounds(rounds: usize) -> usize {
    rounds.max(1)
}

pub(super) fn format_scan_header(
    verb: &str,
    protocol: &str,
    subnet_notation: &str,
    host_count: u64,
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
        let _ = write!(&mut message, " port {p}"); // writing to a String cannot fail
    }

    if let Some(s) = suffix {
        let _ = write!(&mut message, " {s}"); // writing to a String cannot fail
    }

    message
}

pub(super) fn print_host_summary(total: usize, responsive: usize, minimal: bool) {
    let summary = format!(
        "Hosts responsive: {}/{}",
        responsive.to_string().green(),
        total
    );
    print_with_prefix(minimal, &summary);
}

pub(super) fn print_responsive_minimal(hosts: &[IpAddr], responsive: &[bool], minimal: bool) {
    let entries = hosts
        .iter()
        .zip(responsive)
        .filter(|&(_, &up)| up)
        .map(|(ip, _)| ip.to_string().green())
        .collect::<Vec<_>>();
    if entries.is_empty() {
        return;
    }
    let message = format!("[{}]", entries.join(", "));
    print_with_prefix(minimal, &message);
}

pub(super) struct ScanConfig {
    pub(super) notation: String,
    pub(super) host_count: u64,
    too_large: bool,
    pub(super) kind: ProbeKind,
    pub(super) rounds: Option<usize>,
    pub(super) minimal: bool,
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

fn scan_hosts(hosts: &[IpAddr], cfg: &ScanConfig) {
    if print_empty_or_too_large(cfg, hosts) {
        return;
    }

    perform_subnet_watch(hosts, cfg);
}

#[derive(Clone, Copy)]
pub enum Subnet {
    V4(Ipv4Subnet),
    V6(Ipv6Subnet),
}

impl Subnet {
    pub fn notation(self) -> String {
        match self {
            Self::V4(s) => s.notation(),
            Self::V6(s) => s.notation(),
        }
    }

    pub fn host_count(self) -> u64 {
        match self {
            Self::V4(s) => s.host_count(),
            Self::V6(s) => s.host_count(),
        }
    }

    pub fn hosts(self) -> Vec<IpAddr> {
        match self {
            Self::V4(s) => s.iter_hosts().map(IpAddr::V4).collect(),
            Self::V6(s) => s.iter_hosts().map(IpAddr::V6).collect(),
        }
    }
}

pub fn perform_subnet_scan(subnet: Subnet, kind: ProbeKind, rounds: Option<usize>, minimal: bool) {
    let host_count = subnet.host_count();
    scan_hosts(
        &subnet.hosts(),
        &ScanConfig {
            notation: subnet.notation(),
            host_count,
            too_large: matches!(subnet, Subnet::V6(_)) && host_count == u64::MAX,
            kind,
            rounds,
            minimal,
        },
    );
}
