use std::collections::VecDeque;
use std::error::Error;
use std::fmt;
use std::net::{ IpAddr, ToSocketAddrs };
use std::time::{ Duration, Instant };
use ping::ping;
use crate::colors::Colorize;

#[derive(Debug)]
struct MeowpingError(String);

impl fmt::Display for MeowpingError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl Error for MeowpingError {}

pub fn perform_icmp(
    destination: &str,
    timeout_secs: u64,
    ttl: u8,
    ident: u16,
    count: usize,
    payload: &[u8; 24],
    minimal: bool
) -> Result<(), Box<dyn Error>> {
    let ip_addr = resolve_ip(destination)?;
    let timeout = Duration::from_secs(timeout_secs);

    let (successes, times) = execute_pings(
        ip_addr,
        destination,
        timeout,
        ttl,
        ident,
        count,
        payload,
        minimal
    )?;

    print_statistics(count, successes, &times);

    Ok(())
}

fn resolve_ip(destination: &str) -> Result<IpAddr, Box<dyn Error>> {
    if let Ok(ip) = destination.parse::<IpAddr>() {
        Ok(ip)
    } else {
        let addrs = (destination, 0)
            .to_socket_addrs()
            .map_err(|_| Box::new(MeowpingError("Failed to resolve domain".to_string())))?;
        Ok(
            addrs
                .filter_map(|addr| if addr.is_ipv4() { Some(addr.ip()) } else { None })
                .next()
                .ok_or_else(||
                    Box::new(MeowpingError("No valid IPv4 address found for domain".to_string()))
                )?
        )
    }
}

fn execute_pings(
    ip_addr: IpAddr,
    destination: &str,
    timeout: Duration,
    ttl: u8,
    ident: u16,
    count: usize,
    payload: &[u8; 24],
    minimal: bool
) -> Result<(usize, VecDeque<u128>), Box<dyn Error>> {
    let mut times = VecDeque::new();
    let mut successes = 0;

    for seq_cnt in 0..count {
        let duration = measure_ping(ip_addr, timeout, ttl, ident, seq_cnt, payload)?;
        times.push_back(duration);

        let success = duration > 0;
        print_ping_result(success, destination, duration, ttl, ident, seq_cnt, minimal);

        if success {
            successes += 1;
        }

        std::thread::sleep(Duration::from_secs(1));
    }

    Ok((successes, times))
}

fn measure_ping(
    ip_addr: IpAddr,
    timeout: Duration,
    ttl: u8,
    ident: u16,
    seq_cnt: usize,
    payload: &[u8; 24]
) -> Result<u128, Box<dyn Error>> {
    let start = Instant::now();
    let result = ping(
        ip_addr,
        Some(timeout),
        Some(ttl.into()),
        Some(ident),
        Some(seq_cnt as u16),
        Some(payload)
    );
    let duration = start.elapsed().as_micros();

    if result.is_ok() {
        Ok(duration)
    } else {
        Ok(0) // Return 0 for failed pings
    }
}

fn print_ping_result(
    success: bool,
    destination: &str,
    duration: u128,
    ttl: u8,
    ident: u16,
    seq_cnt: usize,
    minimal: bool
) {
    let duration_ms = format!("{:.2}ms", (duration as f32) / 1000.0);
    let ttl_str = ttl.to_string();
    let ident_str = ident.to_string();
    let seq_str = seq_cnt.to_string();

    let message = if success {
        format!(
            "Ping to {}: time={} TTL={} Identifier={} Sequence={}",
            destination.green(),
            duration_ms.green(),
            ttl_str.green(),
            ident_str.green(),
            seq_str.green()
        )
    } else {
        format!(
            "Ping to {} timed out: time={} TTL={} Identifier={} Sequence={}",
            destination.red(),
            duration_ms.red(),
            ttl_str.red(),
            ident_str.red(),
            seq_str.red()
        )
    };

    print_with_prefix(minimal, message);
}

fn print_with_prefix(minimal: bool, message: String) {
    if minimal {
        println!("{}", message);
    } else {
        println!("{} {}", "[MEOWPING]".magenta(), message);
    }
}

fn print_statistics(count: usize, successes: usize, times: &VecDeque<u128>) {
    let failed = count - successes;
    let min_time =
        (
            *times
                .iter()
                .filter(|&&t| t > 0)
                .min()
                .unwrap_or(&0) as f32
        ) / 1000.0;
    let max_time =
        (
            *times
                .iter()
                .filter(|&&t| t > 0)
                .max()
                .unwrap_or(&0) as f32
        ) / 1000.0;
    let avg_time = if successes > 0 {
        (
            (times
                .iter()
                .filter(|&&t| t > 0)
                .sum::<u128>() / (successes as u128)) as f32
        ) / 1000.0
    } else {
        0.0
    };

    println!("\nPing statistics:");
    println!(
        "\tAttempted = {}, Successes = {}, Failures = {} ({}% loss)",
        count.to_string().blue(),
        successes.to_string().blue(),
        failed.to_string().blue(),
        format!("{:.2}%", ((failed as f32) / (count as f32)) * 100.0).blue()
    );
    println!("Approximate round trip times:");
    println!(
        "\tMinimum = {}, Maximum = {}, Average = {}",
        format!("{:.2}ms", min_time).blue(),
        format!("{:.2}ms", max_time).blue(),
        format!("{:.2}ms", avg_time).blue()
    );
}
