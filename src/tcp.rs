use crate::colors::Colorize;
use crate::https::{ self };
use anyhow::Result;
use std::net::{ SocketAddr, TcpStream, ToSocketAddrs };
use std::thread::sleep;
use std::time::{ Duration, Instant };

fn resolve_ip(destination: &str, port: u16) -> Result<SocketAddr> {
    let with_port = format!("{}:{}", destination, port);
    with_port
        .to_socket_addrs()?
        .next()
        .ok_or_else(|| {
            anyhow::anyhow!("Unable to find IP address from domain using default DNS lookup.")
        })
}

fn fetch_asn(ip: &str) -> Result<String> {
    let url = format!("https://ipinfo.io/{}/json", ip);
    let response_text = https::get(&url).map_err(|e| anyhow::anyhow!(e.to_string()))?;

    extract_asn_from_response(&response_text)
}

fn extract_asn_from_response(response_text: &str) -> Result<String> {
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
    Err(anyhow::anyhow!("ASN not found in response"))
}

fn print_ip_info(destination: &str, ip: &str, minimal: bool) {
    let message = format!("Found IP address of domain {}: {}", destination.green(), ip.green());
    println!("{}", if minimal {
        message
    } else {
        format!("{} {}", "[MEOWPING]".magenta(), message)
    });
}

fn perform_connection(
    ip_lookup: SocketAddr,
    port: u16,
    timeout: u64,
    count: usize,
    asn: &str,
    minimal: bool
) -> (usize, f32, f32, f32) {
    let mut successes = 0;
    let mut min_time = f32::MAX;
    let mut max_time = f32::MIN;
    let mut total_time = 0.0;

    for _ in 0..count {
        let duration = measure_connection_time(ip_lookup, port, timeout);
        if duration < min_time {
            min_time = duration;
        }
        if duration > max_time {
            max_time = duration;
        }
        total_time += duration;

        let status_message = format_connection_status(ip_lookup, asn, port, duration, minimal);
        println!("{}", status_message);

        if duration >= 0.0 {
            successes += 1;
        }

        sleep(Duration::from_secs(1));
    }

    let avg_time = if successes > 0 { total_time / (successes as f32) } else { 0.0 };
    (successes, min_time, max_time, avg_time)
}

fn measure_connection_time(ip_lookup: SocketAddr, port: u16, timeout: u64) -> f32 {
    let start = Instant::now();
    let connect_result = TcpStream::connect_timeout(
        &SocketAddr::new(ip_lookup.ip(), port),
        Duration::from_millis(timeout)
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
    minimal: bool
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

fn print_statistics(count: usize, successes: usize, min_time: f32, max_time: f32, avg_time: f32) {
    let failed = count - successes;

    println!("\nConnection statistics:");
    println!(
        "\tAttempted = {}, Connected = {}, Failed = {} ({}% loss)",
        count.to_string().blue(),
        successes.to_string().blue(),
        failed.to_string().blue(),
        format!("{:.2}%", ((failed as f32) / (count as f32)) * 100.0).blue()
    );
    println!("Approximate connection times:");
    println!(
        "\tMinimum = {}, Maximum = {}, Average = {}",
        format!("{:.2}ms", min_time).blue(),
        format!("{:.2}ms", max_time).blue(),
        format!("{:.2}ms", avg_time).blue()
    );
}

pub fn perform_tcp(
    destination: &str,
    port: u16,
    timeout: u64,
    count: usize,
    minimal: bool
) -> Result<()> {
    let ip_lookup = resolve_ip(destination, port)?;

    if ip_lookup.ip().to_string() != destination {
        print_ip_info(destination, &ip_lookup.ip().to_string(), minimal);
    }

    let asn = fetch_asn(&ip_lookup.ip().to_string())?;
    let (successes, min_time, max_time, avg_time) = perform_connection(
        ip_lookup,
        port,
        timeout,
        count,
        &asn,
        minimal
    );
    print_statistics(count, successes, min_time, max_time, avg_time);

    Ok(())
}
