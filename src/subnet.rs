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

#[derive(Clone, Copy, Debug)]
pub struct Ipv4Subnet {
    network: u32,
    prefix: u8,
}

impl Ipv4Subnet {
    pub fn from_str(input: &str) -> Result<Self, &'static str> {
        let trimmed = input.trim();
        let mut parts = trimmed.split('/');
        let ip_part = parts
            .next()
            .ok_or("Missing IPv4 segment in subnet definition")?;
        let prefix_part = parts
            .next()
            .ok_or("Missing prefix length in subnet definition")?;

        if parts.next().is_some() {
            return Err("Too many '/' characters in subnet definition");
        }

        let ip = ip_part
            .parse::<Ipv4Addr>()
            .map_err(|_| "Invalid IPv4 address in subnet definition")?;
        let prefix = prefix_part
            .parse::<u8>()
            .map_err(|_| "Invalid prefix length in subnet definition")?;

        if prefix > 32 {
            return Err("Prefix length must be between 0 and 32");
        }

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

    pub fn iter_hosts(self) -> SubnetHostIter {
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

pub struct SubnetHostIter {
    current: u32,
    end: u32,
    finished: bool,
}

impl SubnetHostIter {
    const fn empty() -> Self {
        Self {
            current: 0,
            end: 0,
            finished: true,
        }
    }
}

impl Iterator for SubnetHostIter {
    type Item = Ipv4Addr;

    fn next(&mut self) -> Option<Self::Item> {
        if self.finished {
            return None;
        }
        if self.current > self.end {
            self.finished = true;
            return None;
        }
        let addr = Ipv4Addr::from(self.current);
        self.current = self.current.wrapping_add(1);
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
        let trimmed = input.trim();
        let mut parts = trimmed.split('/');
        let ip_part = parts
            .next()
            .ok_or("Missing IPv6 segment in subnet definition")?;
        let prefix_part = parts
            .next()
            .ok_or("Missing prefix length in subnet definition")?;

        if parts.next().is_some() {
            return Err("Too many '/' characters in subnet definition");
        }

        let ip = ip_part
            .parse::<Ipv6Addr>()
            .map_err(|_| "Invalid IPv6 address in subnet definition")?;
        let prefix = prefix_part
            .parse::<u8>()
            .map_err(|_| "Invalid prefix length in subnet definition")?;

        if prefix > 128 {
            return Err("Prefix length must be between 0 and 128");
        }

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
            // Too many hosts to reasonably scan
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

    pub fn iter_hosts(&self) -> Ipv6SubnetHostIter {
        let host_bits = 128u32.saturating_sub(u32::from(self.prefix));

        // Limit scanning to reasonable subnet sizes (max /112 = 65536 addresses)
        if host_bits > 16 {
            return Ipv6SubnetHostIter::empty();
        }

        let total_addresses = 1u128 << host_bits;
        if total_addresses == 0 {
            return Ipv6SubnetHostIter::empty();
        }

        let network = self.network;
        let (start, end) = if self.prefix >= 127 {
            (network, network.saturating_add(total_addresses - 1))
        } else {
            if total_addresses <= 2 {
                return Ipv6SubnetHostIter::empty();
            }
            (network + 1, network.saturating_add(total_addresses - 2))
        };

        if start > end {
            return Ipv6SubnetHostIter::empty();
        }

        Ipv6SubnetHostIter {
            current: start,
            end,
            finished: false,
        }
    }
}

pub struct Ipv6SubnetHostIter {
    current: u128,
    end: u128,
    finished: bool,
}

impl Ipv6SubnetHostIter {
    const fn empty() -> Self {
        Self {
            current: 0,
            end: 0,
            finished: true,
        }
    }
}

impl Iterator for Ipv6SubnetHostIter {
    type Item = Ipv6Addr;

    fn next(&mut self) -> Option<Self::Item> {
        if self.finished {
            return None;
        }
        if self.current > self.end {
            self.finished = true;
            return None;
        }
        let addr = Ipv6Addr::from(self.current);
        self.current = self.current.saturating_add(1);
        Some(addr)
    }
}

const DEFAULT_SUBNET_BATCH: usize = 32;

#[derive(Clone, Copy)]
struct HostStatus {
    host: IpAddr,
    latency_us: Option<u128>,
}

fn format_host_status(status: &HostStatus, minimal: bool) -> String {
    status.latency_us.map_or_else(
        || status.host.to_string().red(),
        |latency| {
            let colored_ip = status.host.to_string().green();
            if minimal {
                colored_ip
            } else {
                let ms = micros_to_ms(latency);
                format!("{} {}", colored_ip, color_time(ms))
            }
        },
    )
}

fn print_chunk_row(results: &[HostStatus], minimal: bool, attempt_idx: usize, attempts: usize) {
    if results.is_empty() {
        return;
    }

    let entries = results
        .iter()
        .map(|status| format_host_status(status, minimal))
        .collect::<Vec<_>>()
        .join(", ");

    let mut line = format!("[{entries}]");
    if attempts > 1 {
        line = format!("Attempt {attempt_idx}/{attempts} {line}");
    }

    print_with_prefix(minimal, &line);
}

fn tcp_probe_chunk(hosts: &[IpAddr], port: u16, timeout_ms: u64) -> Vec<HostStatus> {
    let mut handles = Vec::with_capacity(hosts.len());
    for &host in hosts {
        handles.push((
            host,
            thread::spawn(move || {
                tcp_connect_once(host, port, timeout_ms).map_or(
                    HostStatus {
                        host,
                        latency_us: None,
                    },
                    |latency| HostStatus {
                        host,
                        latency_us: Some(latency.as_micros()),
                    },
                )
            }),
        ));
    }

    handles
        .into_iter()
        .map(|(host, handle)| {
            handle.join().unwrap_or(HostStatus {
                host,
                latency_us: None,
            })
        })
        .collect()
}

fn icmp_probe_chunk(
    hosts: &[(IpAddr, u16)],
    timeout: Duration,
    ttl: u8,
    ident: u16,
    payload: &[u8; 24],
) -> Vec<HostStatus> {
    let mut handles = Vec::with_capacity(hosts.len());
    for &(host, seq) in hosts {
        let payload_copy = *payload;
        handles.push((
            host,
            thread::spawn(move || {
                match ping_host_once(host, seq, timeout, ttl, ident, &payload_copy) {
                    Ok((_bytes, rtt)) => HostStatus {
                        host,
                        latency_us: Some(rtt.as_micros()),
                    },
                    Err(_) => HostStatus {
                        host,
                        latency_us: None,
                    },
                }
            }),
        ));
    }

    handles
        .into_iter()
        .map(|(host, handle)| {
            handle.join().unwrap_or(HostStatus {
                host,
                latency_us: None,
            })
        })
        .collect()
}

fn ensure_attempts(attempts: usize) -> usize {
    attempts.max(1)
}

#[derive(Clone, Copy)]
struct UdpHostStatus {
    host: IpAddr,
    outcome: ProbeOutcome,
}

fn format_udp_host_status(status: &UdpHostStatus, minimal: bool) -> String {
    match status.outcome {
        ProbeOutcome::Open { rtt, .. } => {
            let colored_ip = status.host.to_string().green();
            if minimal {
                colored_ip
            } else {
                format!(
                    "{} {}",
                    colored_ip,
                    color_time(micros_to_ms(rtt.as_micros()))
                )
            }
        }
        ProbeOutcome::Closed => format!("{} closed", status.host.to_string().red()),
        ProbeOutcome::NoResponse => format!("{} open|filtered", status.host.to_string().orange()),
    }
}

fn print_udp_chunk_row(
    results: &[UdpHostStatus],
    minimal: bool,
    attempt_idx: usize,
    attempts: usize,
) {
    if results.is_empty() {
        return;
    }

    let entries = results
        .iter()
        .map(|status| format_udp_host_status(status, minimal))
        .collect::<Vec<_>>()
        .join(", ");

    let mut line = format!("[{entries}]");
    if attempts > 1 {
        line = format!("Attempt {attempt_idx}/{attempts} {line}");
    }

    print_with_prefix(minimal, &line);
}

fn udp_probe_chunk(hosts: &[IpAddr], port: u16, timeout: Duration) -> Vec<UdpHostStatus> {
    let payload = crate::udp::probe_payload(port);
    let mut handles = Vec::with_capacity(hosts.len());
    for &host in hosts {
        let payload = payload.clone();
        handles.push((
            host,
            thread::spawn(move || {
                let addr = SocketAddr::new(host, port);
                UdpHostStatus {
                    host,
                    outcome: udp_probe_once(addr, &payload, timeout),
                }
            }),
        ));
    }

    handles
        .into_iter()
        .map(|(host, handle)| {
            handle.join().unwrap_or(UdpHostStatus {
                host,
                outcome: ProbeOutcome::NoResponse,
            })
        })
        .collect()
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

pub fn perform_tcp_subnet_scan(
    subnet: Ipv4Subnet,
    port: u16,
    timeout_ms: u64,
    attempts_per_host: usize,
    minimal: bool,
) {
    let host_count = subnet.host_count();
    if host_count == 0 {
        let message = format!(
            "{} has no usable host addresses",
            subnet.notation().yellow()
        );
        print_with_prefix(minimal, &message);
        return;
    }

    let hosts: Vec<IpAddr> = subnet.iter_hosts().map(IpAddr::V4).collect();
    if hosts.is_empty() {
        let message = format!(
            "{} has no usable host addresses",
            subnet.notation().yellow()
        );
        print_with_prefix(minimal, &message);
        return;
    }

    let subnet_notation = subnet.notation();
    let attempts = ensure_attempts(attempts_per_host);
    print_header(
        "TCP",
        &subnet_notation,
        host_count,
        Some(port),
        attempts,
        minimal,
    );

    let chunk_size = hosts.len().min(DEFAULT_SUBNET_BATCH);
    let mut times = VecDeque::new();
    let mut successes = 0usize;
    let mut responsive_hosts: HashSet<IpAddr> = HashSet::new();

    for attempt_idx in 0..attempts {
        for chunk in hosts.chunks(chunk_size) {
            let results = tcp_probe_chunk(chunk, port, timeout_ms);
            if !minimal {
                print_chunk_row(&results, minimal, attempt_idx + 1, attempts);
            }

            for status in &results {
                if let Some(latency) = status.latency_us {
                    successes += 1;
                    responsive_hosts.insert(status.host);
                    times.push_back(latency);
                } else {
                    times.push_back(0);
                }
            }
        }
    }

    let total_attempts = hosts.len() * attempts;

    if minimal {
        let mut responsive_list: Vec<IpAddr> = responsive_hosts.iter().copied().collect();
        responsive_list.sort_by_key(|ip| match ip {
            IpAddr::V4(v4) => (0, u128::from(u32::from(*v4))),
            IpAddr::V6(v6) => (1, u128::from(*v6)),
        });
        if !responsive_list.is_empty() {
            let entries = responsive_list
                .iter()
                .map(|ip| ip.to_string().green())
                .collect::<Vec<_>>()
                .join(", ");
            let message = format!("[{entries}]");
            print_with_prefix(minimal, &message);
        }
    }

    print_host_summary(hosts.len(), responsive_hosts.len(), minimal);
    print_statistics("TCP subnet", total_attempts, successes, &times);
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
    let host_count = subnet.host_count();
    if host_count == 0 {
        let message = format!(
            "{} has no usable host addresses",
            subnet.notation().yellow()
        );
        print_with_prefix(minimal, &message);
        return;
    }

    let hosts: Vec<IpAddr> = subnet.iter_hosts().map(IpAddr::V4).collect();
    if hosts.is_empty() {
        let message = format!(
            "{} has no usable host addresses",
            subnet.notation().yellow()
        );
        print_with_prefix(minimal, &message);
        return;
    }

    let subnet_notation = subnet.notation();
    let attempts = ensure_attempts(attempts_per_host);
    print_header(
        "ICMP",
        &subnet_notation,
        host_count,
        None,
        attempts,
        minimal,
    );

    let timeout = Duration::from_millis(timeout_ms);
    let chunk_size = hosts.len().min(DEFAULT_SUBNET_BATCH);
    let mut times = VecDeque::new();
    let mut successes = 0usize;
    let mut responsive_hosts: HashSet<IpAddr> = HashSet::new();
    let mut seq: u16 = 1;

    for attempt_idx in 0..attempts {
        for chunk in hosts.chunks(chunk_size) {
            let mut batch = Vec::with_capacity(chunk.len());
            for &host in chunk {
                let current_seq = seq;
                seq = seq.wrapping_add(1);
                batch.push((host, current_seq));
            }

            let results = icmp_probe_chunk(&batch, timeout, ttl, ident, payload);
            if !minimal {
                print_chunk_row(&results, minimal, attempt_idx + 1, attempts);
            }

            for status in &results {
                if let Some(latency) = status.latency_us {
                    successes += 1;
                    responsive_hosts.insert(status.host);
                    times.push_back(latency);
                } else {
                    times.push_back(0);
                }
            }
        }
    }

    let total_attempts = hosts.len() * attempts;

    if minimal {
        let mut responsive_list: Vec<IpAddr> = responsive_hosts.iter().copied().collect();
        responsive_list.sort_by_key(|ip| match ip {
            IpAddr::V4(v4) => (0, u128::from(u32::from(*v4))),
            IpAddr::V6(v6) => (1, u128::from(*v6)),
        });
        if !responsive_list.is_empty() {
            let entries = responsive_list
                .iter()
                .map(|ip| ip.to_string().green())
                .collect::<Vec<_>>()
                .join(", ");
            let message = format!("[{entries}]");
            print_with_prefix(minimal, &message);
        }
    }

    print_host_summary(hosts.len(), responsive_hosts.len(), minimal);
    print_statistics("ICMP subnet", total_attempts, successes, &times);
}

pub fn perform_tcp_ipv6_subnet_scan(
    subnet: &Ipv6Subnet,
    port: u16,
    timeout_ms: u64,
    attempts_per_host: usize,
    minimal: bool,
) {
    let host_count = subnet.host_count();
    if host_count == 0 {
        let message = format!(
            "{} has no usable host addresses",
            subnet.notation().yellow()
        );
        print_with_prefix(minimal, &message);
        return;
    }

    if host_count == u128::MAX {
        let message = format!(
            "{} has too many addresses to scan (max /112 supported)",
            subnet.notation().yellow()
        );
        print_with_prefix(minimal, &message);
        return;
    }

    let hosts: Vec<IpAddr> = subnet.iter_hosts().map(IpAddr::V6).collect();
    if hosts.is_empty() {
        let message = format!(
            "{} has no usable host addresses",
            subnet.notation().yellow()
        );
        print_with_prefix(minimal, &message);
        return;
    }

    let subnet_notation = subnet.notation();
    let attempts = ensure_attempts(attempts_per_host);
    print_header(
        "TCP",
        &subnet_notation,
        host_count,
        Some(port),
        attempts,
        minimal,
    );

    let chunk_size = hosts.len().min(DEFAULT_SUBNET_BATCH);
    let mut times = VecDeque::new();
    let mut successes = 0usize;
    let mut responsive_hosts: HashSet<IpAddr> = HashSet::new();

    for attempt_idx in 0..attempts {
        for chunk in hosts.chunks(chunk_size) {
            let results = tcp_probe_chunk(chunk, port, timeout_ms);
            if !minimal {
                print_chunk_row(&results, minimal, attempt_idx + 1, attempts);
            }

            for status in &results {
                if let Some(latency) = status.latency_us {
                    successes += 1;
                    responsive_hosts.insert(status.host);
                    times.push_back(latency);
                } else {
                    times.push_back(0);
                }
            }
        }
    }

    let total_attempts = hosts.len() * attempts;

    if minimal {
        let mut responsive_list: Vec<IpAddr> = responsive_hosts.iter().copied().collect();
        responsive_list.sort_by_key(|ip| match ip {
            IpAddr::V4(v4) => (0, u128::from(u32::from(*v4))),
            IpAddr::V6(v6) => (1, u128::from(*v6)),
        });
        if !responsive_list.is_empty() {
            let entries = responsive_list
                .iter()
                .map(|ip| ip.to_string().green())
                .collect::<Vec<_>>()
                .join(", ");
            let message = format!("[{entries}]");
            print_with_prefix(minimal, &message);
        }
    }

    print_host_summary(hosts.len(), responsive_hosts.len(), minimal);
    print_statistics("TCP subnet", total_attempts, successes, &times);
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
    if host_count == 0 {
        let message = format!(
            "{} has no usable host addresses",
            subnet.notation().yellow()
        );
        print_with_prefix(minimal, &message);
        return;
    }

    if host_count == u128::MAX {
        let message = format!(
            "{} has too many addresses to scan (max /112 supported)",
            subnet.notation().yellow()
        );
        print_with_prefix(minimal, &message);
        return;
    }

    let hosts: Vec<IpAddr> = subnet.iter_hosts().map(IpAddr::V6).collect();
    if hosts.is_empty() {
        let message = format!(
            "{} has no usable host addresses",
            subnet.notation().yellow()
        );
        print_with_prefix(minimal, &message);
        return;
    }

    let subnet_notation = subnet.notation();
    let attempts = ensure_attempts(attempts_per_host);
    print_header(
        "ICMP",
        &subnet_notation,
        host_count,
        None,
        attempts,
        minimal,
    );

    let timeout = Duration::from_millis(timeout_ms);
    let chunk_size = hosts.len().min(DEFAULT_SUBNET_BATCH);
    let mut times = VecDeque::new();
    let mut successes = 0usize;
    let mut responsive_hosts: HashSet<IpAddr> = HashSet::new();
    let mut seq: u16 = 1;

    for attempt_idx in 0..attempts {
        for chunk in hosts.chunks(chunk_size) {
            let mut batch = Vec::with_capacity(chunk.len());
            for &host in chunk {
                let current_seq = seq;
                seq = seq.wrapping_add(1);
                batch.push((host, current_seq));
            }

            let results = icmp_probe_chunk(&batch, timeout, ttl, ident, payload);
            if !minimal {
                print_chunk_row(&results, minimal, attempt_idx + 1, attempts);
            }

            for status in &results {
                if let Some(latency) = status.latency_us {
                    successes += 1;
                    responsive_hosts.insert(status.host);
                    times.push_back(latency);
                } else {
                    times.push_back(0);
                }
            }
        }
    }

    let total_attempts = hosts.len() * attempts;

    if minimal {
        let mut responsive_list: Vec<IpAddr> = responsive_hosts.iter().copied().collect();
        responsive_list.sort_by_key(|ip| match ip {
            IpAddr::V4(v4) => (0, u128::from(u32::from(*v4))),
            IpAddr::V6(v6) => (1, u128::from(*v6)),
        });
        if !responsive_list.is_empty() {
            let entries = responsive_list
                .iter()
                .map(|ip| ip.to_string().green())
                .collect::<Vec<_>>()
                .join(", ");
            let message = format!("[{entries}]");
            print_with_prefix(minimal, &message);
        }
    }

    print_host_summary(hosts.len(), responsive_hosts.len(), minimal);
    print_statistics("ICMP subnet", total_attempts, successes, &times);
}

pub fn perform_udp_subnet_scan(
    subnet: Ipv4Subnet,
    port: u16,
    timeout_ms: u64,
    attempts_per_host: usize,
    minimal: bool,
) {
    let host_count = subnet.host_count();
    if host_count == 0 {
        let message = format!(
            "{} has no usable host addresses",
            subnet.notation().yellow()
        );
        print_with_prefix(minimal, &message);
        return;
    }

    let hosts: Vec<IpAddr> = subnet.iter_hosts().map(IpAddr::V4).collect();
    if hosts.is_empty() {
        let message = format!(
            "{} has no usable host addresses",
            subnet.notation().yellow()
        );
        print_with_prefix(minimal, &message);
        return;
    }

    let subnet_notation = subnet.notation();
    let attempts = ensure_attempts(attempts_per_host);
    print_header(
        "UDP",
        &subnet_notation,
        host_count,
        Some(port),
        attempts,
        minimal,
    );

    let timeout = Duration::from_millis(timeout_ms);
    let chunk_size = hosts.len().min(DEFAULT_SUBNET_BATCH);
    let mut times = VecDeque::new();
    let mut successes = 0usize;
    let mut responsive_hosts: HashSet<IpAddr> = HashSet::new();

    for attempt_idx in 0..attempts {
        for chunk in hosts.chunks(chunk_size) {
            let results = udp_probe_chunk(chunk, port, timeout);
            if !minimal {
                print_udp_chunk_row(&results, minimal, attempt_idx + 1, attempts);
            }

            for status in &results {
                if let ProbeOutcome::Open { rtt, .. } = status.outcome {
                    successes += 1;
                    responsive_hosts.insert(status.host);
                    times.push_back(rtt.as_micros());
                } else {
                    times.push_back(0);
                }
            }
        }
    }

    let total_attempts = hosts.len() * attempts;

    if minimal {
        let mut responsive_list: Vec<IpAddr> = responsive_hosts.iter().copied().collect();
        responsive_list.sort_by_key(|ip| match ip {
            IpAddr::V4(v4) => (0, u128::from(u32::from(*v4))),
            IpAddr::V6(v6) => (1, u128::from(*v6)),
        });
        if !responsive_list.is_empty() {
            let entries = responsive_list
                .iter()
                .map(|ip| ip.to_string().green())
                .collect::<Vec<_>>()
                .join(", ");
            let message = format!("[{entries}]");
            print_with_prefix(minimal, &message);
        }
    }

    print_host_summary(hosts.len(), responsive_hosts.len(), minimal);
    print_statistics("UDP subnet", total_attempts, successes, &times);
}

pub fn perform_udp_ipv6_subnet_scan(
    subnet: &Ipv6Subnet,
    port: u16,
    timeout_ms: u64,
    attempts_per_host: usize,
    minimal: bool,
) {
    let host_count = subnet.host_count();
    if host_count == 0 {
        let message = format!(
            "{} has no usable host addresses",
            subnet.notation().yellow()
        );
        print_with_prefix(minimal, &message);
        return;
    }

    if host_count == u128::MAX {
        let message = format!(
            "{} has too many addresses to scan (max /112 supported)",
            subnet.notation().yellow()
        );
        print_with_prefix(minimal, &message);
        return;
    }

    let hosts: Vec<IpAddr> = subnet.iter_hosts().map(IpAddr::V6).collect();
    if hosts.is_empty() {
        let message = format!(
            "{} has no usable host addresses",
            subnet.notation().yellow()
        );
        print_with_prefix(minimal, &message);
        return;
    }

    let subnet_notation = subnet.notation();
    let attempts = ensure_attempts(attempts_per_host);
    print_header(
        "UDP",
        &subnet_notation,
        host_count,
        Some(port),
        attempts,
        minimal,
    );

    let timeout = Duration::from_millis(timeout_ms);
    let chunk_size = hosts.len().min(DEFAULT_SUBNET_BATCH);
    let mut times = VecDeque::new();
    let mut successes = 0usize;
    let mut responsive_hosts: HashSet<IpAddr> = HashSet::new();

    for attempt_idx in 0..attempts {
        for chunk in hosts.chunks(chunk_size) {
            let results = udp_probe_chunk(chunk, port, timeout);
            if !minimal {
                print_udp_chunk_row(&results, minimal, attempt_idx + 1, attempts);
            }

            for status in &results {
                if let ProbeOutcome::Open { rtt, .. } = status.outcome {
                    successes += 1;
                    responsive_hosts.insert(status.host);
                    times.push_back(rtt.as_micros());
                } else {
                    times.push_back(0);
                }
            }
        }
    }

    let total_attempts = hosts.len() * attempts;

    if minimal {
        let mut responsive_list: Vec<IpAddr> = responsive_hosts.iter().copied().collect();
        responsive_list.sort_by_key(|ip| match ip {
            IpAddr::V4(v4) => (0, u128::from(u32::from(*v4))),
            IpAddr::V6(v6) => (1, u128::from(*v6)),
        });
        if !responsive_list.is_empty() {
            let entries = responsive_list
                .iter()
                .map(|ip| ip.to_string().green())
                .collect::<Vec<_>>()
                .join(", ");
            let message = format!("[{entries}]");
            print_with_prefix(minimal, &message);
        }
    }

    print_host_summary(hosts.len(), responsive_hosts.len(), minimal);
    print_statistics("UDP subnet", total_attempts, successes, &times);
}
