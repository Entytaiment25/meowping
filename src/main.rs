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
use colors::Colorize;
use http_check::perform_http_check;
use icmp::{DEFAULT_ICMP_PAYLOAD, DEFAULT_IDENT, DEFAULT_TTL, perform_icmp};
use parser::{Extracted, Parser, parse_multiple_destinations};
use subnet::{
    Ipv4Subnet, Ipv6Subnet, perform_icmp_ipv6_subnet_scan, perform_icmp_subnet_scan,
    perform_tcp_ipv6_subnet_scan, perform_tcp_subnet_scan,
};
use tcp::{perform_tcp, perform_tcp_multi_scan};

#[cfg(target_os = "windows")]
use colors::fix_ansicolor;

#[inline(never)]
fn handle_http_check(
    destinations: &[String],
    destination_input: &str,
    timeout: u64,
    count: usize,
    minimal: bool,
    is_multi: bool,
) -> Result<(), Box<dyn Error>> {
    if is_multi {
        for url in destinations {
            let url = if !url.starts_with("http://") && !url.starts_with("https://") {
                format!("http://{}", url)
            } else {
                url.clone()
            };
            let _ = perform_http_check(&url, timeout, count, minimal);
        }
    } else {
        let url = if !destination_input.starts_with("http://")
            && !destination_input.starts_with("https://")
        {
            format!("http://{}", destination_input)
        } else {
            destination_input.to_string()
        };
        perform_http_check(&url, timeout, count, minimal)?;
    }
    Ok(())
}

#[inline(never)]
fn handle_subnet_scan(
    subnet: &Ipv4Subnet,
    port: Option<u16>,
    timeout: u64,
    per_host_attempts: usize,
    minimal: bool,
) -> Result<(), Box<dyn Error>> {
    if let Some(p) = port {
        perform_tcp_subnet_scan(subnet, p, timeout, per_host_attempts, minimal)?;
    } else {
        perform_icmp_subnet_scan(
            subnet,
            timeout,
            DEFAULT_TTL,
            DEFAULT_IDENT,
            per_host_attempts,
            &DEFAULT_ICMP_PAYLOAD,
            minimal,
        )?;
    }
    Ok(())
}

#[inline(never)]
fn handle_ipv6_subnet_scan(
    subnet: &Ipv6Subnet,
    port: Option<u16>,
    timeout: u64,
    per_host_attempts: usize,
    minimal: bool,
) -> Result<(), Box<dyn Error>> {
    if let Some(p) = port {
        perform_tcp_ipv6_subnet_scan(subnet, p, timeout, per_host_attempts, minimal)?;
    } else {
        perform_icmp_ipv6_subnet_scan(
            subnet,
            timeout,
            DEFAULT_TTL,
            DEFAULT_IDENT,
            per_host_attempts,
            &DEFAULT_ICMP_PAYLOAD,
            minimal,
        )?;
    }
    Ok(())
}

#[inline(never)]
fn resolve_destination(dest: &str, minimal: bool) -> Option<String> {
    if dest.parse::<IpAddr>().is_ok() {
        Some(dest.to_string())
    } else {
        match Parser::extract_url(dest) {
            Extracted::Error => {
                let message = format!("DNS Lookup of domain failed: Invalid host or URL: {}", dest);
                if !minimal {
                    println!("{} {}", "[MEOWPING]".magenta(), message);
                } else {
                    println!("{}", message);
                }
                None
            }
            Extracted::Success(host) => Some(host),
        }
    }
}

#[inline(never)]
fn handle_multi_icmp(destinations: &[String], timeout: u64, count: usize, minimal: bool) {
    for dest in destinations {
        if let Some(destination) = resolve_destination(dest, minimal) {
            if !minimal {
                println!(
                    "\n{} Scanning host: {}",
                    "[MEOWPING]".magenta(),
                    destination.green()
                );
            }
            let _ = perform_icmp(
                &destination,
                timeout,
                DEFAULT_TTL,
                DEFAULT_IDENT,
                count,
                &DEFAULT_ICMP_PAYLOAD,
                minimal,
            );
        }
    }
}

#[inline(never)]
fn handle_single_destination(
    destination_input: &str,
    port: Option<u16>,
    timeout: u64,
    count: usize,
    minimal: bool,
    no_asn: bool,
) -> Result<(), Box<dyn Error>> {
    let destination = resolve_destination(destination_input, minimal)
        .ok_or("DNS Lookup of domain failed: Invalid host or URL")?;

    match port {
        Some(p) => perform_tcp(&destination, p, timeout, count.into(), minimal, no_asn)?,
        None => {
            perform_icmp(
                &destination,
                timeout,
                DEFAULT_TTL,
                DEFAULT_IDENT,
                count,
                &DEFAULT_ICMP_PAYLOAD,
                minimal,
            )?;
        }
    }
    Ok(())
}

fn main() -> Result<(), Box<dyn Error>> {
    #[cfg(target_os = "windows")]
    fix_ansicolor::enable_ansi_support();

    let mut args = Arguments::from_env();

    if args.contains(["-h", "--help"]) {
        output::print_help();
        return Ok(());
    }

    let minimal = args.contains(["-m", "--minimal"]);
    let http_check = args.contains(["-s", "--http"]);
    let no_asn = args.contains(["-a", "--no-asn"]);

    let destination_input = args
        .free_from_str::<String>()
        .map_err(|_| "Destination argument missing")?;

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
    let ipv6_subnet_target = if !is_multi && subnet_target.is_none() {
        Ipv6Subnet::from_str(&destination_input).ok()
    } else {
        None
    };

    let timeout = args
        .opt_value_from_str(["-t", "--timeout"])
        .map_err(|_| "Failed to parse timeout argument")?
        .unwrap_or(1000);

    let (count, count_from_cli) = match args.opt_value_from_str(["-c", "--count"]) {
        Ok(Some(c)) => (c, true),
        Ok(None) => (65535, false),
        Err(_) => return Err("Failed to parse count argument".into()),
    };
    let per_host_attempts: usize =
        if (subnet_target.is_some() || ipv6_subnet_target.is_some()) && !count_from_cli {
            1
        } else {
            count as usize
        };

    if http_check {
        if subnet_target.is_some() || ipv6_subnet_target.is_some() {
            return Err("HTTP checking is not supported for subnet targets".into());
        }
        return handle_http_check(
            &destinations,
            &destination_input,
            timeout,
            count as usize,
            minimal,
            is_multi,
        );
    }

    let port = args
        .opt_value_from_str(["-p", "--port"])
        .map_err(|_| "Failed to parse port argument")?;

    if !minimal {
        output::print_welcome();
    }

    if let Some(subnet) = subnet_target {
        return handle_subnet_scan(&subnet, port, timeout, per_host_attempts, minimal);
    }

    if let Some(ipv6_subnet) = ipv6_subnet_target {
        return handle_ipv6_subnet_scan(&ipv6_subnet, port, timeout, per_host_attempts, minimal);
    }

    if is_multi {
        if let Some(p) = port {
            perform_tcp_multi_scan(&destinations, p, timeout, count as usize, minimal, no_asn);
        } else {
            handle_multi_icmp(&destinations, timeout, count as usize, minimal);
        }
    } else {
        handle_single_destination(
            &destination_input,
            port,
            timeout,
            count as usize,
            minimal,
            no_asn,
        )?;
    }

    Ok(())
}
