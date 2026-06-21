#![deny(warnings)]
#![warn(clippy::pedantic, clippy::nursery)]

use std::{error::Error, net::IpAddr};

mod cli;
mod colors;
mod config;
mod http_check;
mod https;
mod icmp;
mod multiport;
mod output;
mod parser;
mod subnet;
mod tcp;
mod udp;

use cli::{Arguments, OptionalFlagValue};
use colors::Colorize;
use http_check::perform_http_check;
use icmp::{DEFAULT_ICMP_PAYLOAD, DEFAULT_IDENT, DEFAULT_TTL, perform_icmp};
use parser::{Extracted, Parser, parse_multiple_destinations, parse_ports};
use subnet::{
    Ipv4Subnet, Ipv6Subnet, perform_icmp_ipv6_subnet_scan, perform_icmp_subnet_scan,
    perform_tcp_ipv6_subnet_scan, perform_tcp_subnet_scan, perform_udp_ipv6_subnet_scan,
    perform_udp_subnet_scan,
};
use tcp::{perform_tcp, perform_tcp_multi_scan};
use udp::{perform_udp, perform_udp_multi_scan};

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
    headers: &[String],
) {
    if is_multi {
        for url in destinations {
            let url = if !url.starts_with("http://") && !url.starts_with("https://") {
                format!("http://{url}")
            } else {
                url.clone()
            };
            perform_http_check(&url, timeout, count, minimal, headers);
        }
    } else {
        let url = if !destination_input.starts_with("http://")
            && !destination_input.starts_with("https://")
        {
            format!("http://{destination_input}")
        } else {
            destination_input.to_string()
        };
        perform_http_check(&url, timeout, count, minimal, headers);
    }
}

#[inline(never)]
fn handle_subnet_scan(
    subnet: Ipv4Subnet,
    port: Option<u16>,
    udp: bool,
    timeout: u64,
    per_host_attempts: usize,
    minimal: bool,
) {
    if let Some(p) = port {
        if udp {
            perform_udp_subnet_scan(subnet, p, timeout, per_host_attempts, minimal);
        } else {
            perform_tcp_subnet_scan(subnet, p, timeout, per_host_attempts, minimal);
        }
    } else {
        perform_icmp_subnet_scan(
            subnet,
            timeout,
            DEFAULT_TTL,
            DEFAULT_IDENT,
            per_host_attempts,
            &DEFAULT_ICMP_PAYLOAD,
            minimal,
        );
    }
}

#[inline(never)]
fn handle_ipv6_subnet_scan(
    subnet: &Ipv6Subnet,
    port: Option<u16>,
    udp: bool,
    timeout: u64,
    per_host_attempts: usize,
    minimal: bool,
) {
    if let Some(p) = port {
        if udp {
            perform_udp_ipv6_subnet_scan(subnet, p, timeout, per_host_attempts, minimal);
        } else {
            perform_tcp_ipv6_subnet_scan(subnet, p, timeout, per_host_attempts, minimal);
        }
    } else {
        perform_icmp_ipv6_subnet_scan(
            subnet,
            timeout,
            DEFAULT_TTL,
            DEFAULT_IDENT,
            per_host_attempts,
            &DEFAULT_ICMP_PAYLOAD,
            minimal,
        );
    }
}

#[inline(never)]
fn resolve_destination(dest: &str, minimal: bool) -> Option<String> {
    // Handle bracketed IPv6 addresses like [::1]
    let clean = if dest.starts_with('[') && dest.ends_with(']') {
        &dest[1..dest.len() - 1]
    } else {
        dest
    };

    if clean.parse::<IpAddr>().is_ok() {
        Some(clean.to_string())
    } else {
        match Parser::extract_url(dest) {
            Extracted::Error => {
                let message = format!("DNS Lookup of domain failed: Invalid host or URL: {dest}");
                if minimal {
                    println!("{message}");
                } else {
                    println!("{} {}", "[MEOWPING]".magenta(), message);
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
    udp: bool,
    timeout: u64,
    count: usize,
    minimal: bool,
    no_asn: bool,
) -> Result<(), Box<dyn Error>> {
    let destination = resolve_destination(destination_input, minimal)
        .ok_or("DNS Lookup of domain failed: Invalid host or URL")?;

    match port {
        Some(p) => {
            if udp {
                perform_udp(&destination, p, timeout, count, minimal, no_asn)?;
            } else {
                perform_tcp(&destination, p, timeout, count, minimal, no_asn)?;
            }
        }
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

fn load_config(args: &mut Arguments) -> Result<Option<config::Config>, Box<dyn Error>> {
    match args.opt_flag_with_optional_value(["-C", "--config"]) {
        OptionalFlagValue::Present(path) => {
            let config_path = std::path::PathBuf::from(path);
            Ok(Some(
                config::Config::load(&config_path).map_err(|e| -> Box<dyn Error> { e.into() })?,
            ))
        }
        OptionalFlagValue::PresentWithoutValue => {
            let config_path = config::Config::default_path();
            if config_path.exists() {
                Ok(Some(
                    config::Config::load(&config_path)
                        .map_err(|e| -> Box<dyn Error> { e.into() })?,
                ))
            } else {
                Ok(None)
            }
        }
        OptionalFlagValue::Missing => Ok(None),
    }
}

fn read_destination(args: &mut Arguments) -> Result<String, Box<dyn Error>> {
    let Ok(destination_input) = args.free_from_str::<String>() else {
        output::print_help();
        #[cfg(target_os = "windows")]
        {
            println!("\nPress Enter to exit...");
            let _ = std::io::stdin().read_line(&mut String::new());
        }
        return Err("Destination argument missing".into());
    };

    Ok(destination_input)
}

fn parse_count(args: &mut Arguments) -> Result<(usize, bool), Box<dyn Error>> {
    match args.opt_value_from_str(["-c", "--count"]) {
        Ok(Some(count)) => Ok((count, true)),
        Ok(None) => Ok((65_535, false)),
        Err(_) => Err("Failed to parse count argument".into()),
    }
}

const MAX_SUBNET_MATRIX: usize = 4096;

#[allow(clippy::struct_excessive_bools)]
struct ProbeCtx<'a> {
    destination_input: &'a str,
    destinations: &'a [String],
    is_multi: bool,
    subnet_target: Option<Ipv4Subnet>,
    ipv6_subnet_target: Option<Ipv6Subnet>,
    ports: Option<Vec<u16>>,
    udp: bool,
    timeout: u64,
    count: usize,
    per_host_attempts: usize,
    minimal: bool,
    no_asn: bool,
}

#[inline(never)]
fn handle_multiport_subnet(ctx: &ProbeCtx<'_>, port_list: &[u16]) -> Result<bool, Box<dyn Error>> {
    if let Some(subnet) = ctx.subnet_target {
        let host_count = subnet.host_count() as usize;
        let matrix = host_count.saturating_mul(port_list.len());
        if matrix > MAX_SUBNET_MATRIX {
            return Err(format!(
                "Subnet x ports matrix too large ({} hosts x {} ports = {}, max {}): narrow the subnet or reduce the ports",
                host_count,
                port_list.len(),
                matrix,
                MAX_SUBNET_MATRIX
            )
            .into());
        }
        multiport::perform_multiport_subnet(
            &subnet.notation(),
            subnet.iter_hosts().map(IpAddr::V4),
            port_list,
            ctx.udp,
            ctx.timeout,
            ctx.per_host_attempts,
            ctx.minimal,
        );
        return Ok(true);
    }
    if let Some(ipv6_subnet) = ctx.ipv6_subnet_target {
        let host_count = ipv6_subnet.host_count();
        if host_count == u128::MAX {
            return Err("IPv6 subnet too large to scan (max /112 supported)".into());
        }
        let matrix =
            host_count.saturating_mul(u128::try_from(port_list.len()).unwrap_or(u128::MAX));
        if matrix > u128::try_from(MAX_SUBNET_MATRIX).unwrap_or(u128::MAX) {
            return Err(format!(
                "IPv6 subnet x ports matrix too large ({} hosts x {} ports = {}, max {}): narrow the subnet or reduce the ports",
                host_count,
                port_list.len(),
                matrix,
                MAX_SUBNET_MATRIX
            )
            .into());
        }
        multiport::perform_multiport_subnet(
            &ipv6_subnet.notation(),
            ipv6_subnet.iter_hosts().map(IpAddr::V6),
            port_list,
            ctx.udp,
            ctx.timeout,
            ctx.per_host_attempts,
            ctx.minimal,
        );
        return Ok(true);
    }
    Ok(false)
}

#[inline(never)]
fn run_probe_dispatch(ctx: &ProbeCtx<'_>) -> Result<(), Box<dyn Error>> {
    match ctx.ports.as_deref() {
        None => run_icmp_dispatch(ctx),
        Some([p]) => run_single_port_dispatch(ctx, *p),
        Some(port_list) => run_multiport_dispatch(ctx, port_list),
    }
}

#[inline(never)]
fn run_icmp_dispatch(ctx: &ProbeCtx<'_>) -> Result<(), Box<dyn Error>> {
    if let Some(subnet) = ctx.subnet_target {
        handle_subnet_scan(
            subnet,
            None,
            ctx.udp,
            ctx.timeout,
            ctx.per_host_attempts,
            ctx.minimal,
        );
        return Ok(());
    }
    if let Some(ipv6_subnet) = ctx.ipv6_subnet_target {
        handle_ipv6_subnet_scan(
            &ipv6_subnet,
            None,
            ctx.udp,
            ctx.timeout,
            ctx.per_host_attempts,
            ctx.minimal,
        );
        return Ok(());
    }
    if ctx.is_multi {
        handle_multi_icmp(ctx.destinations, ctx.timeout, ctx.count, ctx.minimal);
    } else {
        handle_single_destination(
            ctx.destination_input,
            None,
            ctx.udp,
            ctx.timeout,
            ctx.count,
            ctx.minimal,
            ctx.no_asn,
        )?;
    }
    Ok(())
}

#[inline(never)]
fn run_single_port_dispatch(ctx: &ProbeCtx<'_>, p: u16) -> Result<(), Box<dyn Error>> {
    if let Some(subnet) = ctx.subnet_target {
        handle_subnet_scan(
            subnet,
            Some(p),
            ctx.udp,
            ctx.timeout,
            ctx.per_host_attempts,
            ctx.minimal,
        );
        return Ok(());
    }

    if let Some(ipv6_subnet) = ctx.ipv6_subnet_target {
        handle_ipv6_subnet_scan(
            &ipv6_subnet,
            Some(p),
            ctx.udp,
            ctx.timeout,
            ctx.per_host_attempts,
            ctx.minimal,
        );
        return Ok(());
    }

    if ctx.is_multi {
        if ctx.udp {
            perform_udp_multi_scan(
                ctx.destinations,
                p,
                ctx.timeout,
                ctx.count,
                ctx.minimal,
                ctx.no_asn,
            );
        } else {
            perform_tcp_multi_scan(
                ctx.destinations,
                p,
                ctx.timeout,
                ctx.count,
                ctx.minimal,
                ctx.no_asn,
            );
        }
    } else {
        handle_single_destination(
            ctx.destination_input,
            Some(p),
            ctx.udp,
            ctx.timeout,
            ctx.count,
            ctx.minimal,
            ctx.no_asn,
        )?;
    }
    Ok(())
}

#[inline(never)]
fn run_multiport_dispatch(ctx: &ProbeCtx<'_>, port_list: &[u16]) -> Result<(), Box<dyn Error>> {
    if handle_multiport_subnet(ctx, port_list)? {
        return Ok(());
    }
    multiport::perform_multiport_hosts(
        ctx.destinations,
        port_list,
        ctx.udp,
        ctx.timeout,
        ctx.count,
        ctx.minimal,
        ctx.no_asn,
    );
    Ok(())
}

struct ResolvedTargets {
    destinations: Vec<String>,
    is_multi: bool,
    subnet_target: Option<Ipv4Subnet>,
    ipv6_subnet_target: Option<Ipv6Subnet>,
}

fn resolve_targets(destination_input: &str) -> ResolvedTargets {
    let mut destinations = parse_multiple_destinations(destination_input);
    if destinations.len() > 1 {
        use std::collections::HashSet;
        let mut seen = HashSet::new();
        destinations.retain(|d| seen.insert(d.clone()));
    }
    let is_multi = destinations.len() > 1;
    let subnet_target = if is_multi {
        None
    } else {
        Ipv4Subnet::from_str(destination_input).ok()
    };
    let ipv6_subnet_target = if !is_multi && subnet_target.is_none() {
        Ipv6Subnet::from_str(destination_input).ok()
    } else {
        None
    };
    ResolvedTargets {
        destinations,
        is_multi,
        subnet_target,
        ipv6_subnet_target,
    }
}

fn main() -> Result<(), Box<dyn Error>> {
    #[cfg(target_os = "windows")]
    fix_ansicolor::enable_ansi_support();

    let mut args = Arguments::from_env();

    if args.contains(["-h", "--help"]) {
        output::print_help();
        return Ok(());
    }

    let cfg = load_config(&mut args)?;
    let cfg = cfg.as_ref();

    let minimal =
        args.contains(["-m", "--minimal"]) || cfg.and_then(|c| c.minimal).unwrap_or(false);
    let http_check = args.contains(["-s", "--http"]);
    let no_asn = args.contains(["-a", "--no-asn"]) || cfg.and_then(|c| c.no_asn).unwrap_or(false);
    let udp = args.contains(["-u", "--udp"]);

    let destination_input = read_destination(&mut args)?;
    let ResolvedTargets {
        destinations,
        is_multi,
        subnet_target,
        ipv6_subnet_target,
    } = resolve_targets(&destination_input);

    let timeout = args
        .opt_value_from_str(["-t", "--timeout"])
        .map_err(|_| "Failed to parse timeout argument")?
        .unwrap_or(1000);

    let (count, count_from_cli) = parse_count(&mut args)?;
    let per_host_attempts: usize =
        if (subnet_target.is_some() || ipv6_subnet_target.is_some()) && !count_from_cli {
            1
        } else {
            count
        };

    if http_check {
        if subnet_target.is_some() || ipv6_subnet_target.is_some() {
            return Err("HTTP checking is not supported for subnet targets".into());
        }
        let http_headers = cfg.map_or(&[][..], |c| c.http_headers.as_slice());
        handle_http_check(
            &destinations,
            &destination_input,
            timeout,
            count,
            minimal,
            is_multi,
            http_headers,
        );
        return Ok(());
    }

    let ports: Option<Vec<u16>> = args
        .opt_value_from_str::<String, 2>(["-p", "--port"])
        .map_err(|_| "Failed to parse port argument")?
        .map(|s| parse_ports(&s))
        .transpose()?;

    if udp && ports.is_none() {
        return Err("UDP probing requires a port (use -p/--port with --udp)".into());
    }

    if !minimal {
        output::print_welcome();
    }

    let ctx = ProbeCtx {
        destination_input: &destination_input,
        destinations: &destinations,
        is_multi,
        subnet_target,
        ipv6_subnet_target,
        ports,
        udp,
        timeout,
        count,
        per_host_attempts,
        minimal,
        no_asn,
    };

    run_probe_dispatch(&ctx)?;

    Ok(())
}
