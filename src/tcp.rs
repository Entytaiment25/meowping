use crate::colors::Colorize;
use crate::https::{self};
use std::collections::VecDeque;
use std::error::Error;
use std::fmt;
use std::net::{SocketAddr, TcpStream, ToSocketAddrs};
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

fn resolve_ip(destination: &str, port: u16) -> Result<SocketAddr, Box<dyn Error>> {
    if let Ok(ip) = destination.parse::<std::net::IpAddr>() {
        return Ok(SocketAddr::new(ip, port));
    }
    let with_port = format!("{}:{}", destination, port);
    Ok(with_port.to_socket_addrs()?.next().ok_or_else(|| {
        Box::new(MeowpingError(
            "Unable to find IP address from domain.".to_string(),
        ))
    })?)
}

fn is_private_ip(ip_addr: &std::net::IpAddr) -> bool {
    match ip_addr {
        std::net::IpAddr::V4(ip) => ip.is_private(),
        std::net::IpAddr::V6(ip) => ip.is_unique_local(),
    }
}

fn fetch_asn(ip: &str) -> Result<String, Box<dyn Error>> {
    let ip_addr: std::net::IpAddr = ip.parse()?;

    if ip_addr.is_loopback() || is_private_ip(&ip_addr) {
        return Ok("Private/Loopback IP".to_string());
    }

    let url = format!("https://ipinfo.io/{}/json", ip);
    let response_text =
        https::get(&url, 5000).map_err(|e| Box::new(MeowpingError(e.to_string())))?;
    extract_asn_from_response(&response_text)
}

fn extract_asn_from_response(response_text: &str) -> Result<String, Box<dyn Error>> {
    if let Some(start) = response_text.find("\"org\"") {
        let start = response_text[start..]
            .find(':')
            .map(|i| start + i + 1)
            .unwrap_or(0);
        let start = response_text[start..]
            .find('"')
            .map(|i| start + i + 1)
            .unwrap_or(0);
        if let Some(end) = response_text[start..].find('"') {
            return Ok(response_text[start..start + end].trim().to_string());
        }
    }
    Ok("Unknown ASN".to_string())
}

fn print_ip_info(destination: &str, ip: &str, minimal: bool) {
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

fn perform_connection(
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
        times.push_back((duration * 1000.0) as u128);

        let status_message = format_connection_status(ip_lookup, asn, port, duration, minimal);
        println!("{}", status_message);

        if duration >= 0.0 {
            successes += 1;
        }

        sleep(Duration::from_secs(1));
    }

    (successes, times)
}

fn measure_connection_time(ip_lookup: SocketAddr, port: u16, timeout: u64) -> f32 {
    let start = Instant::now();
    let connect_result = TcpStream::connect_timeout(
        &SocketAddr::new(ip_lookup.ip(), port),
        Duration::from_millis(timeout),
    );
    let duration = (start.elapsed().as_micros() as f32) / 1000.0;

    if connect_result.is_err() {
        -1.0
    } else {
        duration
    }
}

fn format_connection_status(
    ip_lookup: SocketAddr,
    asn: &str,
    port: u16,
    duration: f32,
    minimal: bool,
) -> String {
    if duration < 0.0 {
        let status_message = format!(
            "{} timed out ({}): protocol={} port={}",
            ip_lookup.ip().to_string().red(),
            asn.red(),
            "TCP".red(),
            port.to_string().red()
        );
        if minimal {
            status_message
        } else {
            format!("{} {}", "[MEOWPING]".magenta(), status_message)
        }
    } else {
        let status_message = format!(
            "{} ({}): {} protocol={} port={}",
            ip_lookup.ip().to_string().green(),
            asn.green(),
            format!("{:.2}ms", duration).green(),
            "TCP".green(),
            port.to_string().green()
        );
        if minimal {
            status_message
        } else {
            format!("{} {}", "[MEOWPING]".magenta(), status_message)
        }
    }
}

fn print_statistics(count: usize, successes: usize, times: &VecDeque<u128>) {
    let failed = count - successes;

    let min_time = if successes > 0 {
        (*times.iter().filter(|&&t| t > 0).min().unwrap_or(&0) as f32) / 1000.0
    } else {
        0.0
    };

    let max_time = if successes > 0 {
        (*times.iter().filter(|&&t| t > 0).max().unwrap_or(&0) as f32) / 1000.0
    } else {
        0.0
    };

    let avg_time = if successes > 0 {
        (times.iter().filter(|&&t| t > 0).sum::<u128>() as f32) / (successes as f32) / 1000.0
    } else {
        0.0
    };

    println!("\nTCP Ping statistics:");
    println!(
        "\tAttempted = {}, Successes = {}, Failures = {} ({} loss)",
        count.to_string().bright_blue(),
        successes.to_string().bright_blue(),
        failed.to_string().bright_blue(),
        format!("{:.2}%", ((failed as f32) / (count as f32)) * 100.0).bright_blue()
    );
    println!("Approximate round trip times:");
    println!(
        "\tMinimum = {}, Maximum = {}, Average = {}",
        format!("{:.2}ms", min_time).bright_blue(),
        format!("{:.2}ms", max_time).bright_blue(),
        format!("{:.2}ms", avg_time).bright_blue()
    );
}

pub fn perform_tcp(
    destination: &str,
    port: u16,
    timeout: u64,
    count: usize,
    minimal: bool,
) -> Result<(), Box<dyn Error>> {
    let ip_lookup = resolve_ip(destination, port)?;

    if ip_lookup.ip().to_string() != destination {
        print_ip_info(destination, &ip_lookup.ip().to_string(), minimal);
    }

    let asn = fetch_asn(&ip_lookup.ip().to_string())?;
    let (successes, times) = perform_connection(ip_lookup, port, timeout, count, &asn, minimal);
    print_statistics(count, successes, &times);

    Ok(())
}
