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
    payload: &[u8; 24]
) -> Result<()> {
    // Resolve domain to IP address if necessary
    let ip_addr = if let Ok(ip) = destination.parse::<IpAddr>() {
        ip
    } else {
        let addrs = (destination, 0).to_socket_addrs().context("Failed to resolve domain")?;
        addrs
            .filter_map(|addr| if addr.is_ipv4() { Some(addr.ip()) } else { None })
            .next()
            .context("No valid IPv4 address found for domain")?
    };

    let timeout = Duration::from_secs(timeout_secs);
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

        match result {
            Ok(_) => {
                successes += 1;
                println!(
                    "{} Ping to {}: time={} TTL={} Identifier={} Sequence={}",
                    "[MEOWPING]".magenta(),
                    destination.green(),
                    format!("{:.2}ms", (duration as f32) / 1000.0).green(),
                    ttl.to_string().green(),
                    ident.to_string().green(),
                    format!("{}", seq_cnt).green()
                );
            }
            Err(_) => {
                println!(
                    "{} Ping to {} timed out: time={} TTL={} Identifier={} Sequence={}",
                    "[MEOWPING]".magenta(),
                    destination.red(),
                    format!("{:.2}ms", (duration as f32) / 1000.0).red(),
                    ttl.to_string().red(),
                    ident.to_string().red(),
                    format!("{}", seq_cnt).red()
                );
            }
        }
        std::thread::sleep(Duration::from_secs(1));
    }

    let attempted = count;
    let failed = attempted - successes;
    let min_time = (*times.iter().min().unwrap_or(&0) as f32) / 1000.0;
    let max_time = (*times.iter().max().unwrap_or(&0) as f32) / 1000.0;
    let avg_time =
        (
            (if successes > 0 {
                times.iter().sum::<u128>() / (successes as u128)
            } else {
                0
            }) as f32
        ) / 1000.0;

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

    Ok(())
}
