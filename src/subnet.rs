use crate::colors::Colorize;
use crate::icmp::ping_host_once;
use crate::output::{color_time, print_statistics, print_with_prefix};
use crate::tcp::tcp_connect_once;
use std::collections::{HashSet, VecDeque};
use std::error::Error;
use std::net::{IpAddr, Ipv4Addr};
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

    pub fn notation(&self) -> String {
        format!("{}/{}", Ipv4Addr::from(self.network), self.prefix)
    }

    pub fn host_count(&self) -> u128 {
        let host_bits = 32 - (self.prefix as u32);
        let total_addresses = 1u128 << host_bits;

        if self.prefix >= 31 {
            total_addresses
        } else if total_addresses <= 2 {
            0
        } else {
            total_addresses - 2
        }
    }

    pub fn iter_hosts(&self) -> SubnetHostIter {
        let total_addresses = 1u128 << (32 - (self.prefix as u32));
        if total_addresses == 0 {
            return SubnetHostIter::empty();
        }

        let network = self.network as u128;
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
            current: start as u32,
            end: end as u32,
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
    fn empty() -> Self {
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

const DEFAULT_SUBNET_BATCH: usize = 32;

#[derive(Clone, Copy)]
struct HostStatus {
    host: Ipv4Addr,
    latency_us: Option<u128>,
}

fn format_host_status(status: &HostStatus, minimal: bool) -> String {
    if let Some(latency) = status.latency_us {
        let colored_ip = status.host.to_string().green();
        if minimal {
            colored_ip
        } else {
            let ms = (latency as f64) / 1000.0;
            format!("{} {}", colored_ip, color_time(ms))
        }
    } else {
        status.host.to_string().red()
    }
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

    let mut line = format!("[{}]", entries);
    if attempts > 1 {
        line = format!("Attempt {}/{} {}", attempt_idx, attempts, line);
    }

    print_with_prefix(minimal, line);
}

fn tcp_probe_chunk(hosts: &[Ipv4Addr], port: u16, timeout_ms: u64) -> Vec<HostStatus> {
    let mut handles = Vec::with_capacity(hosts.len());
    for &host in hosts {
        handles.push((
            host,
            thread::spawn(move || {
                let latency_ms = tcp_connect_once(IpAddr::V4(host), port, timeout_ms);
                if latency_ms >= 0.0 {
                    let micros = ((latency_ms as f64) * 1000.0).max(0.0) as u128;
                    HostStatus {
                        host,
                        latency_us: Some(micros),
                    }
                } else {
                    HostStatus {
                        host,
                        latency_us: None,
                    }
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

fn icmp_probe_chunk(
    hosts: &[(Ipv4Addr, u16)],
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

fn print_header(
    protocol: &str,
    subnet: &Ipv4Subnet,
    host_count: u128,
    port: Option<u16>,
    attempts: usize,
    minimal: bool,
) {
    let mut message = format!(
        "Scanning {} ({} hosts) via {}",
        subnet.notation().bright_blue(),
        host_count,
        protocol
    );

    if let Some(p) = port {
        message.push_str(&format!(" port {}", p));
    }

    if attempts > 1 {
        message.push_str(&format!(" ({} attempts/host)", attempts));
    }

    print_with_prefix(minimal, message);
}

fn print_host_summary(total: usize, responsive: usize, minimal: bool) {
    let summary = format!(
        "Hosts responsive: {}/{}",
        responsive.to_string().green(),
        total
    );
    print_with_prefix(minimal, summary);
}

pub fn perform_tcp_subnet_scan(
    subnet: &Ipv4Subnet,
    port: u16,
    timeout_ms: u64,
    attempts_per_host: usize,
    minimal: bool,
) -> Result<(), Box<dyn Error>> {
    let host_count = subnet.host_count();
    if host_count == 0 {
        print_with_prefix(
            minimal,
            format!(
                "{} has no usable host addresses",
                subnet.notation().yellow()
            ),
        );
        return Ok(());
    }

    let hosts: Vec<Ipv4Addr> = subnet.iter_hosts().collect();
    if hosts.is_empty() {
        print_with_prefix(
            minimal,
            format!(
                "{} has no usable host addresses",
                subnet.notation().yellow()
            ),
        );
        return Ok(());
    }

    let attempts = ensure_attempts(attempts_per_host);
    print_header("TCP", subnet, host_count, Some(port), attempts, minimal);

    let chunk_size = hosts.len().min(DEFAULT_SUBNET_BATCH);
    let mut times = VecDeque::new();
    let mut successes = 0usize;
    let mut responsive_hosts: HashSet<Ipv4Addr> = HashSet::new();

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
        let mut responsive_list: Vec<Ipv4Addr> = responsive_hosts.iter().cloned().collect();
        responsive_list.sort();
        if !responsive_list.is_empty() {
            let entries = responsive_list
                .iter()
                .map(|ip| ip.to_string().green())
                .collect::<Vec<_>>()
                .join(", ");
            print_with_prefix(minimal, format!("[{}]", entries));
        }
    }

    print_host_summary(hosts.len(), responsive_hosts.len(), minimal);
    print_statistics("TCP subnet", total_attempts, successes, &times);
    Ok(())
}

pub fn perform_icmp_subnet_scan(
    subnet: &Ipv4Subnet,
    timeout_ms: u64,
    ttl: u8,
    ident: u16,
    attempts_per_host: usize,
    payload: &[u8; 24],
    minimal: bool,
) -> Result<(), Box<dyn Error>> {
    let host_count = subnet.host_count();
    if host_count == 0 {
        print_with_prefix(
            minimal,
            format!(
                "{} has no usable host addresses",
                subnet.notation().yellow()
            ),
        );
        return Ok(());
    }

    let hosts: Vec<Ipv4Addr> = subnet.iter_hosts().collect();
    if hosts.is_empty() {
        print_with_prefix(
            minimal,
            format!(
                "{} has no usable host addresses",
                subnet.notation().yellow()
            ),
        );
        return Ok(());
    }

    let attempts = ensure_attempts(attempts_per_host);
    print_header("ICMP", subnet, host_count, None, attempts, minimal);

    let timeout = Duration::from_millis(timeout_ms);
    let chunk_size = hosts.len().min(DEFAULT_SUBNET_BATCH);
    let mut times = VecDeque::new();
    let mut successes = 0usize;
    let mut responsive_hosts: HashSet<Ipv4Addr> = HashSet::new();
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
        let mut responsive_list: Vec<Ipv4Addr> = responsive_hosts.iter().cloned().collect();
        responsive_list.sort();
        if !responsive_list.is_empty() {
            let entries = responsive_list
                .iter()
                .map(|ip| ip.to_string().green())
                .collect::<Vec<_>>()
                .join(", ");
            print_with_prefix(minimal, format!("[{}]", entries));
        }
    }

    print_host_summary(hosts.len(), responsive_hosts.len(), minimal);
    print_statistics("ICMP subnet", total_attempts, successes, &times);
    Ok(())
}
