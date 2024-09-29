use std::collections::VecDeque;
use std::net::{ IpAddr, ToSocketAddrs };
use std::time::{ Duration, Instant };
use ping::ping;
use anyhow::{ Result, Context };
use crate::colors::Colorize;

pub fn perform_icmp(
    destination: &str,
    timeout_secs: u64,
    ttl: u8,
    ident: u16,
    count: usize,
    payload: &[u8; 24],
    minimal: bool
) -> Result<()> {
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

    print_statistics(successes, count, &times);

    Ok(())
}

fn resolve_ip(destination: &str) -> Result<IpAddr> {
    if let Ok(ip) = destination.parse::<IpAddr>() {
        Ok(ip)
    } else {
        let addrs = (destination, 0).to_socket_addrs().context("Failed to resolve domain")?;
        addrs
            .filter_map(|addr| if addr.is_ipv4() { Some(addr.ip()) } else { None })
            .next()
            .context("No valid IPv4 address found for domain")
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
) -> Result<(usize, VecDeque<u128>)> {
    let mut times = VecDeque::new();
    let mut successes = 0;

    for seq_cnt in 0..count {
        let start = Instant::now();
        let result = ping(
            ip_addr,
            Some(timeout),
            Some(ttl.into()),
            Some(ident),
            Some(seq_cnt as u16),
            Some(payload)
        ).context("Ping failed");

        let duration = start.elapsed().as_micros();
        times.push_back(duration);

        print_ping_result(result.is_ok(), destination, duration, ttl, ident, seq_cnt, minimal);
        if result.is_ok() {
            successes += 1;
        }

        std::thread::sleep(Duration::from_secs(1));
    }

    Ok((successes, times))
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

    if success {
        print_with_prefix(
            minimal,
            format!(
                "Ping to {}: time={} TTL={} Identifier={} Sequence={}",
                destination.green(),
                duration_ms.green(),
                ttl_str.green(),
                ident_str.green(),
                seq_str.green()
            )
        );
    } else {
        print_with_prefix(
            minimal,
            format!(
                "Ping to {} timed out: time={} TTL={} Identifier={} Sequence={}",
                destination.red(),
                duration_ms.red(),
                ttl_str.red(),
                ident_str.red(),
                seq_str.red()
            )
        );
    }
}

fn print_with_prefix(minimal: bool, message: String) {
    if !minimal {
        println!("{} {}", "[MEOWPING]".magenta(), message);
    } else {
        println!("{}", message);
    }
}

fn print_statistics(successes: usize, count: usize, times: &VecDeque<u128>) {
    let attempted = count;
    let failed = attempted - successes;
    let min_time = (*times.iter().min().unwrap_or(&0) as f32) / 1000.0;
    let max_time = (*times.iter().max().unwrap_or(&0) as f32) / 1000.0;
    let avg_time = if successes > 0 {
        ((times.iter().sum::<u128>() / (successes as u128)) as f32) / 1000.0
    } else {
        0.0
    };

    println!("\nPing statistics:");
    println!(
        "\tAttempted = {}, Successes = {}, Failures = {} ({}% loss)",
        attempted.to_string().blue(),
        successes.to_string().blue(),
        failed.to_string().blue(),
        format!("{:.2}%", ((failed as f32) / (attempted as f32)) * 100.0).blue()
    );
    println!("Approximate round trip times:");
    println!(
        "\tMinimum = {}, Maximum = {}, Average = {}",
        format!("{:.2}ms", min_time).blue(),
        format!("{:.2}ms", max_time).blue(),
        format!("{:.2}ms", avg_time).blue()
    );
}
