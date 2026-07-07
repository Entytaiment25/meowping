use crate::colors::Colorize;
use crate::icmp::ping_host_once;
use crate::output::{color_time, micros_to_ms, print_statistics, print_with_prefix};
use crate::tcp::tcp_connect_once;
use crate::udp::{ProbeOutcome, udp_probe_once};
use std::collections::{HashSet, VecDeque};
use std::fmt::Write as _;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::thread;
use std::time::Duration;

#[derive(Clone, Copy)]
enum Family {
    V4,
    V6,
}

impl Family {
    const fn missing_segment(self) -> &'static str {
        match self {
            Self::V4 => "Missing IPv4 segment in subnet definition",
            Self::V6 => "Missing IPv6 segment in subnet definition",
        }
    }

    const fn prefix_range(self) -> &'static str {
        match self {
            Self::V4 => "Prefix length must be between 0 and 32",
            Self::V6 => "Prefix length must be between 0 and 128",
        }
    }

    const fn max_prefix(self) -> u8 {
        match self {
            Self::V4 => 32,
            Self::V6 => 128,
        }
    }
}

fn parse_prefix(input: &str, family: Family) -> Result<(&str, u8), &'static str> {
    let trimmed = input.trim();
    let mut parts = trimmed.split('/');
    let ip_part = parts.next().ok_or_else(|| family.missing_segment())?;
    let prefix_part = parts
        .next()
        .ok_or("Missing prefix length in subnet definition")?;

    if parts.next().is_some() {
        return Err("Too many '/' characters in subnet definition");
    }

    let prefix = prefix_part
        .parse::<u8>()
        .map_err(|_| "Invalid prefix length in subnet definition")?;

    if prefix > family.max_prefix() {
        return Err(family.prefix_range());
    }

    Ok((ip_part, prefix))
}

pub trait Word: Copy + PartialOrd {
    type Addr;
    const ZERO: Self;
    fn advance(self) -> Self;
    fn into_addr(self) -> Self::Addr;
}

impl Word for u32 {
    type Addr = Ipv4Addr;
    const ZERO: Self = 0;
    fn advance(self) -> Self {
        self.wrapping_add(1)
    }
    fn into_addr(self) -> Ipv4Addr {
        Ipv4Addr::from(self)
    }
}

impl Word for u128 {
    type Addr = Ipv6Addr;
    const ZERO: Self = 0;
    fn advance(self) -> Self {
        self.saturating_add(1)
    }
    fn into_addr(self) -> Ipv6Addr {
        Ipv6Addr::from(self)
    }
}

#[derive(Clone, Copy, Debug)]
pub struct Ipv4Subnet {
    network: u32,
    prefix: u8,
}

impl Ipv4Subnet {
    pub fn from_str(input: &str) -> Result<Self, &'static str> {
        let (ip_part, prefix) = parse_prefix(input, Family::V4)?;

        let ip = ip_part
            .parse::<Ipv4Addr>()
            .map_err(|_| "Invalid IPv4 address in subnet definition")?;

        let mask = if prefix == 0 {
            0
        } else {
            (!0u32) << (32 - prefix)
        };
        let network = u32::from(ip) & mask;

        Ok(Self { network, prefix })
    }

    pub fn notation(self) -> String {
        format!("{}/{}", Ipv4Addr::from(self.network), self.prefix)
    }

    pub fn host_count(self) -> u128 {
        let host_bits = 32 - u32::from(self.prefix);
        let total_addresses = 1u128 << host_bits;

        if self.prefix >= 31 {
            total_addresses
        } else {
            total_addresses.saturating_sub(2)
        }
    }

    pub fn iter_hosts(self) -> SubnetHostIter<u32> {
        let total_addresses = 1u128 << (32 - u32::from(self.prefix));
        if total_addresses == 0 {
            return SubnetHostIter::empty();
        }

        let network = u128::from(self.network);
        let (start, end) = if self.prefix >= 31 {
            (network, network + total_addresses - 1)
        } else {
            if total_addresses <= 2 {
                return SubnetHostIter::empty();
            }
            (network + 1, network + total_addresses - 2)
        };

        if start > end {
            return SubnetHostIter::empty();
        }

        SubnetHostIter {
            current: u32::try_from(start).expect("IPv4 subnet start address must fit in u32"),
            end: u32::try_from(end).expect("IPv4 subnet end address must fit in u32"),
            finished: false,
        }
    }
}

pub struct SubnetHostIter<W: Word> {
    current: W,
    end: W,
    finished: bool,
}

impl<W: Word> SubnetHostIter<W> {
    const fn empty() -> Self {
        Self {
            current: W::ZERO,
            end: W::ZERO,
            finished: true,
        }
    }
}

impl<W: Word> Iterator for SubnetHostIter<W> {
    type Item = W::Addr;

    fn next(&mut self) -> Option<Self::Item> {
        if self.finished {
            return None;
        }
        if self.current > self.end {
            self.finished = true;
            return None;
        }
        let addr = self.current.into_addr();
        self.current = self.current.advance();
        Some(addr)
    }
}

#[derive(Clone, Copy, Debug)]
pub struct Ipv6Subnet {
    network: u128,
    prefix: u8,
}

impl Ipv6Subnet {
    pub fn from_str(input: &str) -> Result<Self, &'static str> {
        let (ip_part, prefix) = parse_prefix(input, Family::V6)?;

        let ip = ip_part
            .parse::<Ipv6Addr>()
            .map_err(|_| "Invalid IPv6 address in subnet definition")?;

        let mask = if prefix == 0 {
            0
        } else if prefix == 128 {
            !0u128
        } else {
            (!0u128) << (128 - prefix)
        };
        let network = u128::from(ip) & mask;

        Ok(Self { network, prefix })
    }

    pub fn notation(&self) -> String {
        format!("{}/{}", Ipv6Addr::from(self.network), self.prefix)
    }

    pub fn host_count(&self) -> u128 {
        let host_bits = 128u32.saturating_sub(u32::from(self.prefix));
        if host_bits >= 64 {
            return u128::MAX;
        }
        let total_addresses = 1u128 << host_bits;

        if self.prefix >= 127 {
            total_addresses
        } else if total_addresses <= 2 {
            0
        } else {
            total_addresses.saturating_sub(2)
        }
    }

    pub fn iter_hosts(&self) -> SubnetHostIter<u128> {
        let host_bits = 128u32.saturating_sub(u32::from(self.prefix));

        if host_bits > 16 {
            return SubnetHostIter::empty();
        }

        let total_addresses = 1u128 << host_bits;
        if total_addresses == 0 {
            return SubnetHostIter::empty();
        }

        let network = self.network;
        let (start, end) = if self.prefix >= 127 {
            (network, network.saturating_add(total_addresses - 1))
        } else {
            if total_addresses <= 2 {
                return SubnetHostIter::empty();
            }
            (network + 1, network.saturating_add(total_addresses - 2))
        };

        if start > end {
            return SubnetHostIter::empty();
        }

        SubnetHostIter {
            current: start,
            end,
            finished: false,
        }
    }
}

const DEFAULT_SUBNET_BATCH: usize = 32;

enum ProbeKind {
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

    const fn header_protocol(&self) -> &'static str {
        match self {
            Self::Tcp { .. } => "TCP",
            Self::Udp { .. } => "UDP",
            Self::Icmp { .. } => "ICMP",
        }
    }

    const fn header_port(&self) -> Option<u16> {
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
struct ScanResult {
    host: IpAddr,
    verdict: ScanVerdict,
}

impl ScanResult {
    const fn latency_us(&self) -> Option<u128> {
        match self.verdict {
            ScanVerdict::Open { rtt_us } => Some(rtt_us),
            _ => None,
        }
    }

    const fn is_responsive(&self) -> bool {
        matches!(self.verdict, ScanVerdict::Open { .. })
    }

    fn format(&self, minimal: bool) -> String {
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

fn probe_chunk(hosts: &[IpAddr], kind: &ProbeKind, seq: &mut u16) -> Vec<ScanResult> {
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

fn print_header(
    protocol: &str,
    subnet_notation: &str,
    host_count: u128,
    port: Option<u16>,
    attempts: usize,
    minimal: bool,
) {
    let mut message = format!(
        "Scanning {} ({} hosts) via {}",
        subnet_notation.bright_blue(),
        host_count,
        protocol
    );

    if let Some(p) = port {
        write!(&mut message, " port {p}").expect("writing to String should not fail");
    }

    if attempts > 1 {
        write!(&mut message, " ({attempts} attempts/host)")
            .expect("writing to String should not fail");
    }

    print_with_prefix(minimal, &message);
}

fn print_host_summary(total: usize, responsive: usize, minimal: bool) {
    let summary = format!(
        "Hosts responsive: {}/{}",
        responsive.to_string().green(),
        total
    );
    print_with_prefix(minimal, &summary);
}

fn print_responsive_minimal(responsive_hosts: &HashSet<IpAddr>, minimal: bool) {
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

struct ScanConfig {
    notation: String,
    host_count: u128,
    too_large: bool,
    kind: ProbeKind,
    attempts_per_host: usize,
    minimal: bool,
}

fn perform_subnet_scan(hosts: &[IpAddr], cfg: &ScanConfig) {
    if cfg.host_count == 0 {
        let message = format!("{} has no usable host addresses", cfg.notation.yellow());
        print_with_prefix(cfg.minimal, &message);
        return;
    }
    if cfg.too_large {
        let message = format!(
            "{} has too many addresses to scan (max /112 supported)",
            cfg.notation.yellow()
        );
        print_with_prefix(cfg.minimal, &message);
        return;
    }
    if hosts.is_empty() {
        let message = format!("{} has no usable host addresses", cfg.notation.yellow());
        print_with_prefix(cfg.minimal, &message);
        return;
    }

    let attempts = ensure_attempts(cfg.attempts_per_host);
    print_header(
        cfg.kind.header_protocol(),
        &cfg.notation,
        cfg.host_count,
        cfg.kind.header_port(),
        attempts,
        cfg.minimal,
    );

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

pub fn perform_tcp_subnet_scan(
    subnet: Ipv4Subnet,
    port: u16,
    timeout_ms: u64,
    attempts_per_host: usize,
    minimal: bool,
) {
    let hosts: Vec<IpAddr> = subnet.iter_hosts().map(IpAddr::V4).collect();
    perform_subnet_scan(
        &hosts,
        &ScanConfig {
            notation: subnet.notation(),
            host_count: subnet.host_count(),
            too_large: false,
            kind: ProbeKind::Tcp { port, timeout_ms },
            attempts_per_host,
            minimal,
        },
    );
}

pub fn perform_icmp_subnet_scan(
    subnet: Ipv4Subnet,
    timeout_ms: u64,
    ttl: u8,
    ident: u16,
    attempts_per_host: usize,
    payload: &[u8; 24],
    minimal: bool,
) {
    let hosts: Vec<IpAddr> = subnet.iter_hosts().map(IpAddr::V4).collect();
    perform_subnet_scan(
        &hosts,
        &ScanConfig {
            notation: subnet.notation(),
            host_count: subnet.host_count(),
            too_large: false,
            kind: ProbeKind::Icmp {
                timeout: Duration::from_millis(timeout_ms),
                ttl,
                ident,
                payload: *payload,
            },
            attempts_per_host,
            minimal,
        },
    );
}

pub fn perform_tcp_ipv6_subnet_scan(
    subnet: &Ipv6Subnet,
    port: u16,
    timeout_ms: u64,
    attempts_per_host: usize,
    minimal: bool,
) {
    let host_count = subnet.host_count();
    let hosts: Vec<IpAddr> = subnet.iter_hosts().map(IpAddr::V6).collect();
    perform_subnet_scan(
        &hosts,
        &ScanConfig {
            notation: subnet.notation(),
            host_count,
            too_large: host_count == u128::MAX,
            kind: ProbeKind::Tcp { port, timeout_ms },
            attempts_per_host,
            minimal,
        },
    );
}

pub fn perform_icmp_ipv6_subnet_scan(
    subnet: &Ipv6Subnet,
    timeout_ms: u64,
    ttl: u8,
    ident: u16,
    attempts_per_host: usize,
    payload: &[u8; 24],
    minimal: bool,
) {
    let host_count = subnet.host_count();
    let hosts: Vec<IpAddr> = subnet.iter_hosts().map(IpAddr::V6).collect();
    perform_subnet_scan(
        &hosts,
        &ScanConfig {
            notation: subnet.notation(),
            host_count,
            too_large: host_count == u128::MAX,
            kind: ProbeKind::Icmp {
                timeout: Duration::from_millis(timeout_ms),
                ttl,
                ident,
                payload: *payload,
            },
            attempts_per_host,
            minimal,
        },
    );
}

pub fn perform_udp_subnet_scan(
    subnet: Ipv4Subnet,
    port: u16,
    timeout_ms: u64,
    attempts_per_host: usize,
    minimal: bool,
) {
    let hosts: Vec<IpAddr> = subnet.iter_hosts().map(IpAddr::V4).collect();
    perform_subnet_scan(
        &hosts,
        &ScanConfig {
            notation: subnet.notation(),
            host_count: subnet.host_count(),
            too_large: false,
            kind: ProbeKind::Udp {
                port,
                timeout: Duration::from_millis(timeout_ms),
            },
            attempts_per_host,
            minimal,
        },
    );
}

pub fn perform_udp_ipv6_subnet_scan(
    subnet: &Ipv6Subnet,
    port: u16,
    timeout_ms: u64,
    attempts_per_host: usize,
    minimal: bool,
) {
    let host_count = subnet.host_count();
    let hosts: Vec<IpAddr> = subnet.iter_hosts().map(IpAddr::V6).collect();
    perform_subnet_scan(
        &hosts,
        &ScanConfig {
            notation: subnet.notation(),
            host_count,
            too_large: host_count == u128::MAX,
            kind: ProbeKind::Udp {
                port,
                timeout: Duration::from_millis(timeout_ms),
            },
            attempts_per_host,
            minimal,
        },
    );
}
