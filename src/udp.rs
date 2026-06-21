use crate::colors::Colorize;
use crate::output::{color_time, micros_to_ms, print_statistics, print_with_prefix};
use crate::tcp::{fetch_asn, resolve_ip};
use std::collections::{HashSet, VecDeque};
use std::io::ErrorKind;
use std::net::{IpAddr, SocketAddr, UdpSocket};
use std::thread::sleep;
use std::time::{Duration, Instant};

const DNS_QUERY: [u8; 17] = [
    0xab, 0xcd, // ID
    0x01, 0x00, // flags: standard query, recursion desired
    0x00, 0x01, // QDCOUNT = 1
    0x00, 0x00, // ANCOUNT = 0
    0x00, 0x00, // NSCOUNT = 0
    0x00, 0x00, // ARCOUNT = 0
    0x00, // root label (empty name)
    0x00, 0x01, // QTYPE = A
    0x00, 0x01, // QCLASS = IN
];

const NTP_REQUEST: [u8; 48] = {
    let mut a = [0u8; 48];
    a[0] = 0x1B; // 00 011 011 = LI 0, version 3, mode 3 (client)
    a
};

#[derive(Clone, Copy, Debug)]
pub enum ProbeOutcome {
    Open { rtt: Duration, bytes: usize },
    Closed,
    NoResponse,
}

pub fn probe_payload(port: u16) -> Vec<u8> {
    match port {
        53 => DNS_QUERY.to_vec(),
        123 => NTP_REQUEST.to_vec(),
        _ => vec![0x00],
    }
}

pub fn udp_probe_once(addr: SocketAddr, payload: &[u8], timeout: Duration) -> ProbeOutcome {
    let bind_addr = if addr.is_ipv4() {
        "0.0.0.0:0"
    } else {
        "[::]:0"
    };
    let Ok(sock) = UdpSocket::bind(bind_addr) else {
        return ProbeOutcome::NoResponse;
    };
    if sock.connect(addr).is_err() {
        return ProbeOutcome::NoResponse;
    }
    if sock.set_read_timeout(Some(timeout)).is_err() {
        return ProbeOutcome::NoResponse;
    }

    let start = Instant::now();
    if let Err(e) = sock.send(payload) {
        if e.kind() == ErrorKind::ConnectionRefused {
            return ProbeOutcome::Closed;
        }
        return ProbeOutcome::NoResponse;
    }

    let mut buf = [0u8; 1500];
    match sock.recv(&mut buf) {
        Ok(n) => ProbeOutcome::Open {
            rtt: start.elapsed(),
            bytes: n,
        },
        Err(e) if e.kind() == ErrorKind::ConnectionRefused => ProbeOutcome::Closed,
        Err(_) => ProbeOutcome::NoResponse,
    }
}

fn format_udp_status(
    ip: IpAddr,
    asn: &str,
    port: u16,
    outcome: &ProbeOutcome,
    minimal: bool,
) -> String {
    let show_asn = !minimal || asn != "no lookup";
    let prefix = if minimal {
        String::new()
    } else {
        format!("{} ", "[MEOWPING]".magenta())
    };
    let proto = "UDP";

    match outcome {
        ProbeOutcome::Open { rtt, bytes } => {
            let time_colored = color_time(rtt.as_secs_f64() * 1000.0);
            let body = if show_asn {
                format!(
                    "{} ({}): {} protocol={} port={} bytes={}",
                    ip.to_string().green(),
                    asn.green(),
                    time_colored,
                    proto.green(),
                    port.to_string().green(),
                    bytes
                )
            } else {
                format!(
                    "{}: {} protocol={} port={} bytes={}",
                    ip.to_string().green(),
                    time_colored,
                    proto.green(),
                    port.to_string().green(),
                    bytes
                )
            };
            format!("{prefix}{body}")
        }
        ProbeOutcome::Closed => {
            let body = if show_asn {
                format!(
                    "{} closed (Port Unreachable) ({}): protocol={} port={}",
                    ip.to_string().red(),
                    asn.red(),
                    proto.red(),
                    port.to_string().red()
                )
            } else {
                format!(
                    "{} closed (Port Unreachable): protocol={} port={}",
                    ip.to_string().red(),
                    proto.red(),
                    port.to_string().red()
                )
            };
            format!("{prefix}{body}")
        }
        ProbeOutcome::NoResponse => {
            let body = if show_asn {
                format!(
                    "{} no response (open|filtered) ({}): protocol={} port={}",
                    ip.to_string().orange(),
                    asn.orange(),
                    proto.orange(),
                    port.to_string().orange()
                )
            } else {
                format!(
                    "{} no response (open|filtered): protocol={} port={}",
                    ip.to_string().orange(),
                    proto.orange(),
                    port.to_string().orange()
                )
            };
            format!("{prefix}{body}")
        }
    }
}

pub fn perform_udp(
    destination: &str,
    port: u16,
    timeout: u64,
    count: usize,
    minimal: bool,
    no_asn: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    let ip_lookup = resolve_ip(destination, port)?;

    if ip_lookup.ip().to_string() != destination {
        crate::tcp::print_ip_info(destination, &ip_lookup.ip().to_string(), minimal);
    }

    let asn = fetch_asn(&ip_lookup.ip().to_string(), no_asn, timeout)?;
    let payload = probe_payload(port);
    let timeout_dur = Duration::from_millis(timeout);

    let mut times: VecDeque<u128> = VecDeque::new();
    let mut successes = 0usize;

    for attempt_idx in 0..count {
        let outcome = udp_probe_once(ip_lookup, &payload, timeout_dur);
        let is_open = matches!(outcome, ProbeOutcome::Open { .. });
        let entry = format_udp_status(ip_lookup.ip(), &asn, port, &outcome, minimal);
        println!("{entry}");

        if is_open {
            successes += 1;
            if let ProbeOutcome::Open { rtt, .. } = outcome {
                times.push_back(rtt.as_micros());
            }
        } else {
            times.push_back(0);
        }

        if attempt_idx + 1 != count {
            sleep(Duration::from_secs(1));
        }
    }

    print_statistics("UDP", count, successes, &times);
    Ok(())
}

fn udp_multi_entry(
    host: &str,
    asn: &str,
    outcome: &ProbeOutcome,
    port: u16,
) -> (Option<u128>, String) {
    match outcome {
        ProbeOutcome::Open { rtt, bytes } => {
            let latency_micros = rtt.as_micros();
            let entry = format!(
                "  {} ({}): {} protocol={} port={} bytes={}",
                host.green(),
                asn.green(),
                color_time(micros_to_ms(latency_micros)),
                "UDP".green(),
                port.to_string().green(),
                bytes
            );
            (Some(latency_micros), entry)
        }
        ProbeOutcome::Closed => {
            let entry = format!(
                "  {} closed (Port Unreachable) ({}): protocol={} port={}",
                host.red(),
                asn.red(),
                "UDP".red(),
                port.to_string().red()
            );
            (None, entry)
        }
        ProbeOutcome::NoResponse => {
            let entry = format!(
                "  {} no response (open|filtered) ({}): protocol={} port={}",
                host.orange(),
                asn.orange(),
                "UDP".orange(),
                port.to_string().orange()
            );
            (None, entry)
        }
    }
}

pub fn perform_udp_multi_scan(
    hosts: &[String],
    port: u16,
    timeout_ms: u64,
    attempts_per_host: usize,
    minimal: bool,
    no_asn: bool,
) {
    let attempts = attempts_per_host.max(1);
    let chunk_size = hosts.len().min(32);
    let mut times = VecDeque::new();
    let mut successes = 0usize;
    let mut responsive_hosts: HashSet<String> = HashSet::new();
    let payload = probe_payload(port);
    let timeout_dur = Duration::from_millis(timeout_ms);

    for attempt_idx in 0..attempts {
        if !minimal && attempts > 1 {
            let message = format!("Attempt {}/{}", attempt_idx + 1, attempts);
            print_with_prefix(minimal, &message);
        }
        for chunk in hosts.chunks(chunk_size) {
            let mut results = Vec::with_capacity(chunk.len());
            for host in chunk {
                let host = host.clone();
                let Ok(ip) = resolve_ip(&host, port) else {
                    let entry = format!(
                        "  {} no response (open|filtered) ({}): protocol={} port={}",
                        host.orange(),
                        "resolve error".orange(),
                        "UDP".orange(),
                        port.to_string().orange()
                    );
                    print_with_prefix(minimal, &entry);
                    results.push((host.clone(), None));
                    sleep(Duration::from_secs(1));
                    continue;
                };
                let asn = fetch_asn(&ip.ip().to_string(), no_asn, timeout_ms)
                    .unwrap_or_else(|_| "?".to_string());
                let outcome = udp_probe_once(ip, &payload, timeout_dur);
                let (latency_micros, entry) = udp_multi_entry(&host, &asn, &outcome, port);
                print_with_prefix(minimal, &entry);
                results.push((host.clone(), latency_micros));
                sleep(Duration::from_secs(1));
            }
            for (host, latency_micros) in &results {
                if let Some(latency) = latency_micros {
                    successes += 1;
                    responsive_hosts.insert(host.clone());
                    times.push_back(*latency);
                } else {
                    times.push_back(0);
                }
            }
        }
    }
    let total_attempts = hosts.len() * attempts;
    if minimal {
        let mut responsive_list: Vec<String> = responsive_hosts.iter().cloned().collect();
        responsive_list.sort();
        if !responsive_list.is_empty() {
            let entries = responsive_list
                .iter()
                .map(|ip| ip.green())
                .collect::<Vec<_>>()
                .join(", ");
            let message = format!("[{entries}]");
            print_with_prefix(minimal, &message);
        }
    }
    let summary = format!(
        "Hosts responsive: {}/{}",
        responsive_hosts.len().to_string().green(),
        hosts.len()
    );
    print_with_prefix(minimal, &summary);
    print_statistics("UDP multi", total_attempts, successes, &times);
}
