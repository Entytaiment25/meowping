fn perform_tcp_multi_scan(
    hosts: &[String],
    port: u16,
    timeout_ms: u64,
    attempts_per_host: usize,
    minimal: bool,
    no_asn: bool,
) {
    use std::collections::{HashSet, VecDeque};
    use crate::tcp::{resolve_ip, fetch_asn};
    use crate::colors::Colorize;
    use crate::output::{print_statistics, print_with_prefix};

    let attempts = attempts_per_host.max(1);
    let chunk_size = hosts.len().min(32);
    let mut times = VecDeque::new();
    let mut successes = 0usize;
    let mut responsive_hosts: HashSet<String> = HashSet::new();

    for attempt_idx in 0..attempts {
        if !minimal && attempts > 1 {
            print_with_prefix(minimal, format!("Attempt {}/{}", attempt_idx + 1, attempts));
        }
        for chunk in hosts.chunks(chunk_size) {
            let mut results = Vec::with_capacity(chunk.len());
            for host in chunk {
                let host = host.clone();
                let ip: std::net::SocketAddr = match resolve_ip(&host, port) {
                    Ok(ip) => ip,
                    Err(_) => {
                        let entry = format!("  {} timed out ({}): protocol={} port={}", host.red(), "resolve error".red(), "TCP".red(), port.to_string().red());
                        print_with_prefix(minimal, entry);
                        results.push((host.clone(), None, "resolve error".to_string()));
                        std::thread::sleep(std::time::Duration::from_millis(1000));
                        continue;
                    }
                };
                let asn = fetch_asn(&ip.ip().to_string(), no_asn).unwrap_or_else(|_| "?".to_string());
                let latency_ms = crate::tcp::tcp_connect_once(ip.ip(), port, timeout_ms);
                let (latency_us, entry) = if latency_ms >= 0.0 {
                    let us = (latency_ms * 1000.0) as u128;
                    (Some(us), format!("  {} ({}): {} protocol={} port={}", host.green(), asn.green(), crate::output::color_time((us as f64) / 1000.0), "TCP".green(), port.to_string().green()))
                } else {
                    (None, format!("  {} timed out ({}): protocol={} port={}", host.red(), asn.red(), "TCP".red(), port.to_string().red()))
                };
                print_with_prefix(minimal, entry);
                results.push((host.clone(), latency_us, asn));
                std::thread::sleep(std::time::Duration::from_millis(1000));
            }
            for (host, latency_us, _) in &results {
                if let Some(lat) = latency_us {
                    successes += 1;
                    responsive_hosts.insert(host.clone());
                    times.push_back(*lat);
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
            print_with_prefix(minimal, format!("[{}]", entries));
        }
    }
    print_with_prefix(minimal, format!("Hosts responsive: {}/{}", responsive_hosts.len().to_string().green(), hosts.len()));
    print_statistics("TCP multi", total_attempts, successes, &times);
}
use std::{error::Error, net::IpAddr};

mod cli;
mod colors;
mod http_check;
mod https;
mod icmp;
mod output;
mod parser;
mod subnet;
mod tcp;

use cli::Arguments;
use colors::{Colorize, HyperLink};
use http_check::perform_http_check;
use icmp::perform_icmp;
use parser::{Extracted, Parser};
use subnet::{Ipv4Subnet, perform_icmp_subnet_scan, perform_tcp_subnet_scan};
use tcp::perform_tcp;

#[cfg(target_os = "windows")]
use colors::fix_ansicolor;

fn parse_multiple_destinations(input: &str) -> Vec<String> {
    let trimmed = input.trim();
    if trimmed.starts_with('[') && trimmed.ends_with(']') {
        trimmed[1..trimmed.len() - 1]
            .split(',')
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .collect()
    } else if trimmed.contains(',') {
        trimmed
            .split(',')
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .collect()
    } else {
        vec![trimmed.to_string()]
    }
}

fn main() -> Result<(), Box<dyn Error>> {
    #[cfg(target_os = "windows")]
    fix_ansicolor::enable_ansi_support();
    let version_format = format!("v.{}", env!("CARGO_PKG_VERSION"));
    let name = env!("CARGO_PKG_NAME");

    let mut args = Arguments::from_env();

    if args.contains(["-h", "--help"]) {
        println!("Usage: {} <destination> [options]\n", name);
        println!("Optional Options:");
        println!(
            "{:>30}",
            "    -h, --help                Prints the Help Menu"
        );
        println!(
            "{:>30}",
            "    -p, --port <port>         Set the port number (default: ICMP, with: TCP)"
        );
        println!(
            "{:>30}",
            "    -t, --timeout <timeout>   Set the timeout for each connection attempt in milliseconds (default: 1000ms)"
        );
        println!(
            "{:>30}",
            "    -c, --count <count>       Set the number of connection attempts (default: 65535)"
        );
        println!(
            "{:>30}",
            "    -m, --minimal             Changes the Prints to be more Minimal"
        );
        println!(
            "{:>30}",
            "    -s, --http              Check if the destination URL is online via HTTP/S"
        );
        println!(
            "{:>30}",
            "    -a, --no-asn            Disable ASN/organization lookups (use static data)"
        );
        return Ok(());
    }

    let minimal = args.contains(["-m", "--minimal"]);
    let http_check = args.contains(["-s", "--http"]);
    let no_asn = args.contains(["-a", "--no-asn"]);

    let destination_input = match args.free_from_str::<String>() {
        Ok(dest) => dest,
        Err(_) => {
            return Err("Destination argument missing".into());
        }
    };

    let mut destinations = parse_multiple_destinations(&destination_input);
    if destinations.len() > 1 {
        use std::collections::HashSet;
        let mut seen = HashSet::new();
        destinations.retain(|d| seen.insert(d.clone()));
    }
    let is_multi = destinations.len() > 1;
    let subnet_target = if !is_multi {
        Ipv4Subnet::from_str(&destination_input).ok()
    } else {
        None
    };

    let timeout = match args.opt_value_from_str(["-t", "--timeout"]) {
        Ok(Some(t)) => t,
        Ok(None) => 1000,
        Err(_) => {
            return Err("Failed to parse timeout argument".into());
        }
    };
    let (count, count_from_cli) = match args.opt_value_from_str(["-c", "--count"]) {
        Ok(Some(c)) => (c, true),
        Ok(None) => (65535, false),
        Err(_) => {
            return Err("Failed to parse count argument".into());
        }
    };
    let per_host_attempts = if subnet_target.is_some() && !count_from_cli {
        1
    } else {
        count
    };

    if http_check {
        if subnet_target.is_some() {
            return Err("HTTP checking is not supported for subnet targets".into());
        }
        if is_multi {
            for url in &destinations {
                let mut url = url.clone();
                if !url.starts_with("http://") && !url.starts_with("https://") {
                    url = format!("http://{}", url);
                }
                let _ = perform_http_check(&url, timeout, count, minimal);
            }
            return Ok(());
        } else {
            let mut url = destination_input.clone();
            if !url.starts_with("http://") && !url.starts_with("https://") {
                url = format!("http://{}", url);
            }
            return perform_http_check(&url, timeout, count, minimal);
        }
    }

    let port = match args.opt_value_from_str(["-p", "--port"]) {
        Ok(opt) => opt,
        Err(_) => {
            return Err("Failed to parse port argument".into());
        }
    };

    if !minimal {
        let hyperlink = HyperLink::new(name, "https://github.com/entytaiment25/meowping")
            .expect("valid hyperlink");

        let message = format!(
            "
    ／l、
  （ﾟ､ ｡ ７      welcome to {}!
    l  ~ヽ       {}
    じしf_,)ノ
",
            hyperlink, version_format
        )
        .magenta();

        println!("{}", message);
    }

    if let Some(subnet) = subnet_target {
        if let Some(p) = port {
            perform_tcp_subnet_scan(&subnet, p, timeout, per_host_attempts, minimal)?;
        } else {
            let ttl = 64;
            let ident = 0;
            let payload: [u8; 24] = [
                46, 46, 46, 109, 101, 111, 119, 46, 46, 46, 109, 101, 111, 119, 46, 46, 46, 109,
                101, 111, 119, 46, 46, 46,
            ];
            perform_icmp_subnet_scan(
                &subnet,
                timeout,
                ttl,
                ident,
                per_host_attempts,
                &payload,
                minimal,
            )?;
        }
        return Ok(());
    }

    if is_multi {
        if let Some(p) = port {
            perform_tcp_multi_scan(&destinations, p, timeout, count, minimal, no_asn);
        } else {
            for dest in &destinations {
                let destination = if dest.parse::<IpAddr>().is_ok() {
                    dest.clone()
                } else {
                    match Parser::extract_url(dest) {
                        Extracted::Error => {
                            let message = format!("DNS Lookup of domain failed: Invalid host or URL: {}", dest);
                            if !minimal {
                                println!("{} {}", "[MEOWPING]".magenta(), message);
                            } else {
                                println!("{}", message);
                            }
                            continue;
                        }
                        Extracted::Success(host) => host,
                    }
                };
                if !minimal {
                    println!("\n[MEOWPING] Scanning host: {}", destination.green());
                }
                let ttl = 64;
                let ident = 0;
                let payload: [u8; 24] = [
                    46, 46, 46, 109, 101, 111, 119, 46, 46, 46, 109, 101, 111, 119, 46, 46, 46, 109,
                    101, 111, 119, 46, 46, 46,
                ];
                let _ = perform_icmp(&destination, timeout, ttl, ident, count, &payload, minimal);
            }
        }
        return Ok(());
    } else {
        let destination = if destination_input.parse::<IpAddr>().is_ok() {
            destination_input.clone()
        } else {
            match Parser::extract_url(&destination_input) {
                Extracted::Error => {
                    let message = "DNS Lookup of domain failed: Invalid host or URL";
                    if !minimal {
                        println!("{} {}", "[MEOWPING]".magenta(), message);
                    } else {
                        println!("{}", message);
                    }
                    return Ok(());
                }
                Extracted::Success(host) => host,
            }
        };
        match port {
            Some(p) => perform_tcp(&destination, p, timeout, count.into(), minimal, no_asn)?,
            None => {
                let ttl = 64;
                let ident = 0;
                let payload: [u8; 24] = [
                    46, 46, 46, 109, 101, 111, 119, 46, 46, 46, 109, 101, 111, 119, 46, 46, 46, 109,
                    101, 111, 119, 46, 46, 46,
                ];
                perform_icmp(&destination, timeout, ttl, ident, count, &payload, minimal)?;
            }
        }
    }

    Ok(())
}
