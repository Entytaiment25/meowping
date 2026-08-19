use crate::colors::Colorize;
use crate::output::{PingStats, color_time, format_with_prefix, print_statistics};
use crate::parser::{Extracted, Parser};
use std::error::Error;
use std::io::ErrorKind;
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4, UdpSocket};
use std::thread::sleep;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

pub const DEFAULT_DNS_SERVER: SocketAddr =
    SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(1, 1, 1, 1), 53));

const fn rcode_name(rcode: u8) -> &'static str {
    match rcode {
        0 => "NOERROR",
        1 => "FORMERR",
        2 => "SERVFAIL",
        3 => "NXDOMAIN",
        4 => "NOTIMP",
        5 => "REFUSED",
        _ => "UNKNOWN",
    }
}

fn build_query(id: u16, domain: &str) -> Option<Vec<u8>> {
    let mut buf = Vec::with_capacity(12 + domain.len() + 6);
    buf.extend_from_slice(&id.to_be_bytes());
    buf.extend_from_slice(&[0x01, 0x00]); // flags: recursion desired
    buf.extend_from_slice(&[0x00, 0x01]); // QDCOUNT = 1
    buf.extend_from_slice(&[0x00, 0x00]); // ANCOUNT
    buf.extend_from_slice(&[0x00, 0x00]); // NSCOUNT
    buf.extend_from_slice(&[0x00, 0x00]); // ARCOUNT

    for label in domain.trim_end_matches('.').split('.') {
        if label.is_empty() || label.len() > 63 {
            return None;
        }
        buf.push(u8::try_from(label.len()).ok()?);
        buf.extend_from_slice(label.as_bytes());
    }
    buf.push(0x00);
    buf.extend_from_slice(&[0x00, 0x01]); // QTYPE = A
    buf.extend_from_slice(&[0x00, 0x01]); // QCLASS = IN

    Some(buf)
}

struct DnsAnswer {
    rcode: u8,
    ancount: u16,
}

fn parse_response(buf: &[u8], expected_id: u16) -> Option<DnsAnswer> {
    if buf.len() < 12 {
        return None;
    }
    if u16::from_be_bytes([buf[0], buf[1]]) != expected_id {
        return None;
    }
    let flags = u16::from_be_bytes([buf[2], buf[3]]);
    if flags >> 15 != 1 {
        return None;
    }
    Some(DnsAnswer {
        rcode: u8::try_from(flags & 0x0F).expect("4-bit mask fits in u8"),
        ancount: u16::from_be_bytes([buf[6], buf[7]]),
    })
}

enum DnsOutcome {
    Resolved { rtt: Duration, ancount: u16 },
    Negative { rtt: Duration, rcode: u8 },
    NoResponse,
}

fn dns_probe_once(query: &[u8], id: u16, timeout: Duration, dns_server: SocketAddr) -> DnsOutcome {
    let bind_addr = if dns_server.is_ipv4() {
        "0.0.0.0:0"
    } else {
        "[::]:0"
    };
    let Ok(sock) = UdpSocket::bind(bind_addr) else {
        return DnsOutcome::NoResponse;
    };
    if sock.connect(dns_server).is_err() {
        return DnsOutcome::NoResponse;
    }
    if sock.set_read_timeout(Some(timeout)).is_err() {
        return DnsOutcome::NoResponse;
    }

    let start = Instant::now();
    if sock.send(query).is_err() {
        return DnsOutcome::NoResponse;
    }

    let mut buf = [0u8; 512];
    let n = match sock.recv(&mut buf) {
        Ok(n) => n,
        Err(e) if e.kind() == ErrorKind::WouldBlock || e.kind() == ErrorKind::TimedOut => {
            return DnsOutcome::NoResponse;
        }
        Err(_) => return DnsOutcome::NoResponse,
    };
    let rtt = start.elapsed();

    match parse_response(&buf[..n], id) {
        Some(answer) if answer.rcode == 0 => DnsOutcome::Resolved {
            rtt,
            ancount: answer.ancount,
        },
        Some(answer) => DnsOutcome::Negative {
            rtt,
            rcode: answer.rcode,
        },
        None => DnsOutcome::NoResponse,
    }
}

fn format_dns_status(
    domain: &str,
    outcome: &DnsOutcome,
    minimal: bool,
    dns_server: SocketAddr,
) -> String {
    let resolver = dns_server.ip().to_string();

    let body = match outcome {
        DnsOutcome::Resolved { rtt, ancount } => {
            let time_colored = color_time(rtt.as_secs_f64() * 1000.0);
            format!(
                "{} : {} protocol=DNS domain={} rcode={} answers={}",
                resolver.green(),
                time_colored,
                domain.green(),
                "NOERROR".green(),
                ancount
            )
        }
        DnsOutcome::Negative { rtt, rcode } => {
            let time_colored = color_time(rtt.as_secs_f64() * 1000.0);
            format!(
                "{} : {} protocol=DNS domain={} rcode={}",
                resolver.orange(),
                time_colored,
                domain.orange(),
                rcode_name(*rcode).orange()
            )
        }
        DnsOutcome::NoResponse => {
            format!(
                "{} timed out: protocol=DNS domain={}",
                resolver.red(),
                domain.red()
            )
        }
    };

    format_with_prefix(minimal, &body)
}

pub fn perform_dns(
    destination: &str,
    timeout: u64,
    count: usize,
    minimal: bool,
    dns_server: SocketAddr,
) -> Result<(), Box<dyn Error>> {
    let domain = match Parser::extract_url(destination) {
        Extracted::Success(host) => host,
        Extracted::Error => {
            let message =
                format!("DNS Lookup of domain failed: Invalid host or URL: {destination}");
            println!("{}", format_with_prefix(minimal, &message));
            return Ok(());
        }
    };

    let seed = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0xABCD, |d| {
            u16::try_from(d.subsec_nanos() & 0xFFFF).unwrap_or(0xABCD)
        });
    let timeout_dur = Duration::from_millis(timeout);

    let mut stats = PingStats::default();
    let mut id = seed;

    for attempt_idx in 0..count {
        let Some(query) = build_query(id, &domain) else {
            return Err(format!("Invalid domain for DNS query: {domain}").into());
        };

        let outcome = dns_probe_once(&query, id, timeout_dur, dns_server);
        let is_success = matches!(outcome, DnsOutcome::Resolved { .. });
        let entry = format_dns_status(&domain, &outcome, minimal, dns_server);
        println!("{entry}");

        stats.record(
            is_success,
            match outcome {
                DnsOutcome::Resolved { rtt, .. } | DnsOutcome::Negative { rtt, .. } => {
                    Some(rtt.as_micros())
                }
                DnsOutcome::NoResponse => None,
            },
        );

        if attempt_idx + 1 != count {
            sleep(Duration::from_secs(1));
        }
        id = id.wrapping_add(1);
    }

    print_statistics("DNS", &stats);
    Ok(())
}
