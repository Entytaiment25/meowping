use crate::asn_cache;
use crate::colors::Colorize;
use crate::https;
use crate::output::{PingStats, color_time, print_statistics};
use std::error::Error;
use std::fmt;
use std::net::{IpAddr, SocketAddr, TcpStream, ToSocketAddrs};
use std::thread::sleep;
use std::time::{Duration, Instant};

#[derive(Debug)]
struct MeowpingError(String);

impl fmt::Display for MeowpingError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl Error for MeowpingError {}

pub fn resolve_ip(destination: &str, port: u16) -> Result<SocketAddr, Box<dyn Error>> {
    if let Ok(ip) = destination.parse::<std::net::IpAddr>() {
        return Ok(SocketAddr::new(ip, port));
    }
    let with_port = if destination.contains(':') {
        format!("[{destination}]:{port}")
    } else {
        format!("{destination}:{port}")
    };
    let addrs: Vec<SocketAddr> = with_port.to_socket_addrs()?.collect();
    let chosen = addrs
        .iter()
        .find(|a| a.is_ipv4())
        .or_else(|| addrs.first())
        .ok_or_else(|| {
            Box::new(MeowpingError(
                "Unable to find IP address from domain.".to_string(),
            ))
        })?;
    Ok(*chosen)
}

const fn is_private_ip(ip_addr: &std::net::IpAddr) -> bool {
    match ip_addr {
        std::net::IpAddr::V4(ip) => ip.is_private(),
        std::net::IpAddr::V6(ip) => ip.is_unique_local(),
    }
}

pub fn fetch_asn(ip: &str, no_api: bool, timeout: u64) -> Result<String, Box<dyn Error>> {
    let ip_addr: std::net::IpAddr = ip.parse()?;

    if ip_addr.is_loopback() || is_private_ip(&ip_addr) {
        return Ok("Private/Loopback IP".to_string());
    }

    if no_api {
        return Ok("no lookup".to_string());
    }

    if let Some(org) = asn_cache::get(ip_addr) {
        return Ok(org);
    }

    let url = format!("https://ipinfo.io/{ip}/json");
    let response_text =
        https::get(&url, timeout).map_err(|e| Box::new(MeowpingError(e.to_string())))?;
    // No "org" (for example a rate limit reply) is not cached, so the next run retries.
    let Some(org) = extract_asn_from_response(&response_text) else {
        return Ok("Unknown ASN".to_string());
    };
    asn_cache::put(ip_addr, &org);
    Ok(org)
}

fn extract_asn_from_response(response_text: &str) -> Option<String> {
    let start = response_text.find("\"org\"")?;
    let start = response_text[start..]
        .find(':')
        .map_or(0, |i| start + i + 1);
    let start = response_text[start..]
        .find('"')
        .map_or(0, |i| start + i + 1);
    let end = response_text[start..].find('"')?;
    Some(response_text[start..start + end].trim().to_string())
}

pub fn print_ip_info(destination: &str, ip: &str, minimal: bool) {
    let message = format!(
        "Found IP address of domain {}: {}",
        destination.green(),
        ip.green()
    );
    println!(
        "{}",
        if minimal {
            message
        } else {
            format!("{} {}", "[MEOWPING]".magenta(), message)
        }
    );
}

pub fn perform_connection(
    ip_lookup: SocketAddr,
    port: u16,
    timeout: u64,
    count: usize,
    asn: &str,
    minimal: bool,
) -> PingStats {
    let mut stats = PingStats::default();

    for attempt_idx in 0..count {
        let duration = measure_connection_time(ip_lookup, port, timeout);
        stats.record(duration.is_some(), duration.map(|d| d.as_micros()));

        let status_message = format_connection_status(ip_lookup, asn, port, duration, minimal);
        println!("{status_message}");

        if attempt_idx + 1 != count {
            sleep(Duration::from_secs(1));
        }
    }

    stats
}

fn measure_connection_time(ip_lookup: SocketAddr, port: u16, timeout: u64) -> Option<Duration> {
    tcp_connect_once(ip_lookup.ip(), port, timeout)
}

pub fn tcp_connect_once(ip: IpAddr, port: u16, timeout: u64) -> Option<Duration> {
    let start = Instant::now();
    let connect_result =
        TcpStream::connect_timeout(&SocketAddr::new(ip, port), Duration::from_millis(timeout));

    if connect_result.is_err() {
        None
    } else {
        Some(start.elapsed())
    }
}

fn format_connection_status(
    ip_lookup: SocketAddr,
    asn: &str,
    port: u16,
    duration: Option<Duration>,
    minimal: bool,
) -> String {
    let show_asn = !minimal || asn != "no lookup";
    let prefix = if minimal {
        String::new()
    } else {
        format!("{} ", "[MEOWPING]".magenta())
    };

    duration.map_or_else(
        || {
            let status_message = if show_asn {
                format!(
                    "{} timed out ({}): protocol={} port={}",
                    ip_lookup.ip().to_string().red(),
                    asn.red(),
                    "TCP".red(),
                    port.to_string().red()
                )
            } else {
                format!(
                    "{} timed out: protocol={} port={}",
                    ip_lookup.ip().to_string().red(),
                    "TCP".red(),
                    port.to_string().red()
                )
            };
            format!("{prefix}{status_message}")
        },
        |rtt| {
            let time_colored = color_time(rtt.as_secs_f64() * 1000.0);
            let status_message = if show_asn {
                format!(
                    "{} ({}): {} protocol={} port={}",
                    ip_lookup.ip().to_string().green(),
                    asn.green(),
                    time_colored,
                    "TCP".green(),
                    port.to_string().green()
                )
            } else {
                format!(
                    "{}: {} protocol={} port={}",
                    ip_lookup.ip().to_string().green(),
                    time_colored,
                    "TCP".green(),
                    port.to_string().green()
                )
            };
            format!("{prefix}{status_message}")
        },
    )
}

pub fn perform_tcp(
    destination: &str,
    port: u16,
    timeout: u64,
    count: usize,
    minimal: bool,
    no_asn: bool,
) -> Result<(), Box<dyn Error>> {
    let ip_lookup = resolve_ip(destination, port)?;

    if ip_lookup.ip().to_string() != destination {
        print_ip_info(destination, &ip_lookup.ip().to_string(), minimal);
    }

    let asn = fetch_asn(&ip_lookup.ip().to_string(), no_asn, timeout)?;
    let stats = perform_connection(ip_lookup, port, timeout, count, &asn, minimal);
    print_statistics("TCP", &stats);

    Ok(())
}

pub fn perform_tcp_multi_scan(
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
        false,
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
    fn extracts_org_and_rejects_replies_without_it() {
        assert_eq!(
            extract_asn_from_response(r#"{"ip": "1.1.1.1", "org": "AS13335 Cloudflare, Inc."}"#)
                .as_deref(),
            Some("AS13335 Cloudflare, Inc.")
        );
        assert_eq!(
            extract_asn_from_response(r#"{"error": {"title": "Rate limit exceeded"}}"#),
            None
        );
    }

    #[test]
    fn multi_scan_probes_hosts_in_parallel() {
        let hosts: Vec<String> = ["127.0.0.1", "127.0.0.2", "127.0.0.3", "127.0.0.4"]
            .iter()
            .map(ToString::to_string)
            .collect();
        let start = Instant::now();
        perform_tcp_multi_scan(&hosts, 1, 200, 2, true, true);
        let elapsed = start.elapsed();
        assert!(
            elapsed.as_secs() < 4,
            "multi scan should probe hosts in parallel, took {elapsed:?}"
        );
    }
}
