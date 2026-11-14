use crate::asn_cache;
use crate::colors::Colorize;
use crate::https;
use crate::output::{PingStats, TIME_COLUMN_WIDTH, color_time_padded, micros, print_statistics};
use std::error::Error;
use std::net::{IpAddr, SocketAddr, TcpStream, ToSocketAddrs};
use std::sync::{Arc, OnceLock};
use std::thread::{self, sleep};
use std::time::{Duration, Instant};

pub fn resolve_ip(destination: &str, port: u16) -> Result<SocketAddr, Box<dyn Error>> {
    if let Ok(ip) = destination.parse::<IpAddr>() {
        return Ok(SocketAddr::new(ip, port));
    }
    let addrs: Vec<SocketAddr> = (destination, port).to_socket_addrs()?.collect();
    let chosen = addrs
        .iter()
        .find(|a| a.is_ipv4())
        .or_else(|| addrs.first())
        .ok_or("Unable to find IP address from domain.")?;
    Ok(*chosen)
}

const fn is_private_ip(ip_addr: &IpAddr) -> bool {
    match ip_addr {
        IpAddr::V4(ip) => ip.is_private(),
        IpAddr::V6(ip) => ip.is_unique_local(),
    }
}

pub fn fetch_asn(ip: &str, no_api: bool, timeout: u64) -> Result<String, Box<dyn Error>> {
    let ip_addr: IpAddr = ip.parse()?;

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
    let response_text = https::get(&url, timeout).map_err(|e| e.to_string())?;
    // No "org" (for example a rate limit reply) is not cached, so the next run retries.
    let Some(org) = extract_asn_from_response(&response_text) else {
        return Ok("Unknown ASN".to_string());
    };
    asn_cache::put(ip_addr, &org);
    Ok(org)
}

/// Runs the ASN lookup on a background thread so pinging can start right away.
/// Until the result arrives the label is empty and lines are printed without it.
pub struct AsnLookup {
    result: Arc<OnceLock<String>>,
}

impl AsnLookup {
    pub fn spawn(ip: String, no_api: bool, timeout: u64) -> Self {
        let result = Arc::new(OnceLock::new());
        let slot = Arc::clone(&result);
        let waiter = thread::current();
        thread::spawn(move || {
            let org = fetch_asn(&ip, no_api, timeout).unwrap_or_else(|_| "Unknown ASN".to_string());
            let _ = slot.set(org);
            waiter.unpark();
        });
        Self { result }
    }

    pub fn label_final(&self) -> &str {
        self.result.wait()
    }

    /// The label so far. Cached, private and `-a` lookups finish within the grace
    /// period, so only a real network lookup can leave the first lines without it.
    pub fn label(&self) -> &str {
        let deadline = Instant::now() + Duration::from_millis(25);
        loop {
            if let Some(org) = self.result.get() {
                return org;
            }
            let left = deadline.saturating_duration_since(Instant::now());
            if left.is_zero() {
                return "";
            }
            thread::park_timeout(left);
        }
    }
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
    asn: &AsnLookup,
    minimal: bool,
) -> PingStats {
    let mut stats = PingStats::default();

    for attempt_idx in 0..count {
        let duration = measure_connection_time(ip_lookup, port, timeout);
        stats.record(duration.is_some(), duration.map(micros));

        let label = if attempt_idx + 1 == count {
            asn.label_final()
        } else {
            asn.label()
        };
        let status_message = format_connection_status(ip_lookup, label, port, duration, minimal);
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
    let show_asn = !asn.is_empty() && (!minimal || asn != "no lookup");
    let prefix = if minimal {
        String::new()
    } else {
        format!("{} ", "[MEOWPING]".magenta())
    };
    let paint: fn(&str) -> String = if duration.is_some() {
        str::green
    } else {
        str::red
    };
    let asn_part = if show_asn {
        format!(" ({})", paint(asn))
    } else {
        String::new()
    };
    let time = duration.map_or_else(
        || format!("{:>TIME_COLUMN_WIDTH$}", "timed out").red(),
        |rtt| color_time_padded(micros(rtt), TIME_COLUMN_WIDTH),
    );

    format!(
        "{prefix}{}{asn_part}: {time} protocol={} port={}",
        paint(&ip_lookup.ip().to_string()),
        paint("TCP"),
        paint(&port.to_string())
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

    let asn = AsnLookup::spawn(ip_lookup.ip().to_string(), no_asn, timeout);
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
