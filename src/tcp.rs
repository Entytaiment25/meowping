use crate::colors::Colorize;
use crate::https;
use crate::output::{color_time, micros_to_ms, print_statistics};
use std::collections::VecDeque;
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

    let url = format!("https://ipinfo.io/{ip}/json");
    let response_text =
        https::get(&url, timeout).map_err(|e| Box::new(MeowpingError(e.to_string())))?;
    Ok(extract_asn_from_response(&response_text))
}

fn extract_asn_from_response(response_text: &str) -> String {
    if let Some(start) = response_text.find("\"org\"") {
        let start = response_text[start..]
            .find(':')
            .map_or(0, |i| start + i + 1);
        let start = response_text[start..]
            .find('"')
            .map_or(0, |i| start + i + 1);
        if let Some(end) = response_text[start..].find('"') {
            return response_text[start..start + end].trim().to_string();
        }
    }
    "Unknown ASN".to_string()
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
) -> (usize, VecDeque<u128>) {
    let mut successes = 0;
    let mut times = VecDeque::new();

    for _ in 0..count {
        let duration = measure_connection_time(ip_lookup, port, timeout);
        if let Some(rtt) = duration {
            times.push_back(rtt.as_micros());
        } else {
            times.push_back(0);
        }

        let status_message = format_connection_status(ip_lookup, asn, port, duration, minimal);
        println!("{status_message}");

        if duration.is_some() {
            successes += 1;
        }

        sleep(Duration::from_secs(1));
    }

    (successes, times)
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
    let (successes, times) = perform_connection(ip_lookup, port, timeout, count, &asn, minimal);
    print_statistics("TCP", count, successes, &times);

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
    use crate::output::print_with_prefix;
    use std::collections::HashSet;

    let attempts = attempts_per_host.max(1);
    let chunk_size = hosts.len().min(32);
    let mut times = VecDeque::new();
    let mut successes = 0usize;
    let mut responsive_hosts: HashSet<String> = HashSet::new();

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
                        "  {} timed out ({}): protocol={} port={}",
                        host.red(),
                        "resolve error".red(),
                        "TCP".red(),
                        port.to_string().red()
                    );
                    print_with_prefix(minimal, &entry);
                    results.push((host.clone(), None, "resolve error".to_string()));
                    sleep(Duration::from_secs(1));
                    continue;
                };
                let asn = fetch_asn(&ip.ip().to_string(), no_asn, timeout_ms)
                    .unwrap_or_else(|_| "?".to_string());
                let latency = tcp_connect_once(ip.ip(), port, timeout_ms);
                let (latency_micros, entry) = latency.map_or_else(
                    || {
                        (
                            None,
                            format!(
                                "  {} timed out ({}): protocol={} port={}",
                                host.red(),
                                asn.red(),
                                "TCP".red(),
                                port.to_string().red()
                            ),
                        )
                    },
                    |rtt| {
                        let latency_micros = rtt.as_micros();
                        (
                            Some(latency_micros),
                            format!(
                                "  {} ({}): {} protocol={} port={}",
                                host.green(),
                                asn.green(),
                                color_time(micros_to_ms(latency_micros)),
                                "TCP".green(),
                                port.to_string().green()
                            ),
                        )
                    },
                );
                print_with_prefix(minimal, &entry);
                results.push((host.clone(), latency_micros, asn));
                sleep(Duration::from_secs(1));
            }
            for (host, latency_micros, _) in &results {
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
    print_statistics("TCP multi", total_attempts, successes, &times);
}
