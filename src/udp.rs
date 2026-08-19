use crate::colors::Colorize;
use crate::output::{PingStats, color_time, print_statistics};
use crate::tcp::{fetch_asn, resolve_ip};
use std::borrow::Cow;
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

pub const fn probe_payload(port: u16) -> Cow<'static, [u8]> {
    match port {
        53 => Cow::Borrowed(&DNS_QUERY),
        123 => Cow::Borrowed(&NTP_REQUEST),
        _ => Cow::Borrowed(&[0x00]),
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

    let mut stats = PingStats::default();

    for attempt_idx in 0..count {
        let outcome = udp_probe_once(ip_lookup, &payload, timeout_dur);
        let is_open = matches!(outcome, ProbeOutcome::Open { .. });
        let entry = format_udp_status(ip_lookup.ip(), &asn, port, &outcome, minimal);
        println!("{entry}");

        stats.record(is_open, outcome_rtt(&outcome));

        if attempt_idx + 1 != count {
            sleep(Duration::from_secs(1));
        }
    }

    print_statistics("UDP", &stats);
    Ok(())
}

const fn outcome_rtt(outcome: &ProbeOutcome) -> Option<u128> {
    match outcome {
        ProbeOutcome::Open { rtt, .. } => Some(rtt.as_micros()),
        ProbeOutcome::Closed | ProbeOutcome::NoResponse => None,
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
    crate::multiport::perform_host_scan(
        hosts,
        port,
        true,
        timeout_ms,
        attempts_per_host,
        minimal,
        no_asn,
    );
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Instant;

    #[test]
    fn multi_scan_probes_hosts_in_parallel() {
        let hosts: Vec<String> = ["127.0.0.1", "127.0.0.2", "127.0.0.3", "127.0.0.4"]
            .iter()
            .map(ToString::to_string)
            .collect();
        let start = Instant::now();
        perform_udp_multi_scan(&hosts, 9, 200, 2, true, true);
        let elapsed = start.elapsed();
        assert!(
            elapsed.as_secs() < 4,
            "multi scan should probe hosts in parallel, took {elapsed:?}"
        );
    }
}
