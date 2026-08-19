#![deny(warnings)]
#![warn(clippy::pedantic, clippy::nursery)]

use std::{error::Error, net::IpAddr};

mod cli;
mod colors;
mod config;
mod dns;
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
use dns::perform_dns;
use http_check::perform_http_check;
use icmp::{CLASSIC_ICMP_PAYLOAD, DEFAULT_IDENT, DEFAULT_TTL, MEOW_ICMP_PAYLOAD, perform_icmp};
use parser::{Extracted, Parser, parse_multiple_destinations, parse_ports};
use subnet::{Ipv4Subnet, Ipv6Subnet, ProbeKind, Subnet, perform_subnet_scan};
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

const fn probe_kind_for(
    port: Option<u16>,
    udp: bool,
    timeout: u64,
    payload: [u8; 24],
) -> ProbeKind {
    match port {
        Some(p) if udp => ProbeKind::udp(p, timeout),
        Some(p) => ProbeKind::tcp(p, timeout),
        None => ProbeKind::icmp(timeout, DEFAULT_TTL, DEFAULT_IDENT, payload),
    }
}

fn handle_subnet_scan(
    subnet: Subnet,
    port: Option<u16>,
    udp: bool,
    timeout: u64,
    rounds: Option<usize>,
    minimal: bool,
    payload: &[u8; 24],
) {
    perform_subnet_scan(
        subnet,
        probe_kind_for(port, udp, timeout, *payload),
        rounds,
        minimal,
    );
}

#[inline(never)]
fn resolve_destination(dest: &str, minimal: bool) -> Option<String> {
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
                output::print_resolution_failure(dest, minimal);
                None
            }
            Extracted::Success(host) => Some(host),
        }
    }
}

#[inline(never)]
fn handle_multi_icmp(
    destinations: &[String],
    timeout: u64,
    attempts: usize,
    minimal: bool,
    payload: &[u8; 24],
) {
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
                attempts,
                payload,
                minimal,
            );
        }
    }
}

#[inline(never)]
#[allow(clippy::too_many_arguments)]
fn handle_single_destination(
    destination_input: &str,
    port: Option<u16>,
    udp: bool,
    timeout: u64,
    count: usize,
    minimal: bool,
    no_asn: bool,
    payload: &[u8; 24],
) -> Result<(), Box<dyn Error>> {
    let Some(destination) = resolve_destination(destination_input, minimal) else {
        return Ok(());
    };

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
                payload,
                minimal,
            )?;
        }
    }
    Ok(())
}

fn load_config(args: &mut Arguments) -> Result<Option<config::Config>, Box<dyn Error>> {
    let (config_path, missing_ok, parse_fatal) =
        match args.opt_flag_with_optional_value(["-C", "--config"]) {
            OptionalFlagValue::Present(path) => (std::path::PathBuf::from(path), false, true),
            OptionalFlagValue::PresentWithoutValue => (config::Config::default_path(), true, true),
            OptionalFlagValue::Missing => (config::Config::default_path(), true, false),
        };
    if missing_ok && !config_path.exists() {
        return Ok(None);
    }
    match config::Config::load(&config_path) {
        Ok(cfg) => Ok(Some(cfg)),
        Err(e) if parse_fatal => Err(e.into()),
        Err(e) => {
            eprintln!(
                "{} Ignoring '{}': {e}",
                "[MEOWPING]".magenta(),
                config_path.display()
            );
            Ok(None)
        }
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

fn validate_timeout(timeout: u64) -> Result<(), String> {
    if timeout == 0 {
        Err("timeout must be at least 1ms (-t/--timeout)".to_string())
    } else {
        Ok(())
    }
}

const fn compute_per_host_attempts(scan_like: bool, explicit_count: bool, count: usize) -> usize {
    if scan_like && !explicit_count {
        1
    } else {
        count
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
    explicit_count: bool,
    payload: &'a [u8; 24],
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
            ctx.no_asn,
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
            ctx.no_asn,
        );
        return Ok(true);
    }
    Ok(false)
}

#[inline(never)]
fn run_probe_dispatch(ctx: &ProbeCtx<'_>) -> Result<(), Box<dyn Error>> {
    match ctx.ports.as_deref() {
        None => run_host_dispatch(ctx, None),
        Some([p]) => run_host_dispatch(ctx, Some(*p)),
        Some(port_list) => run_multiport_dispatch(ctx, port_list),
    }
}

#[inline(never)]
fn run_host_dispatch(ctx: &ProbeCtx<'_>, port: Option<u16>) -> Result<(), Box<dyn Error>> {
    let rounds = ctx.explicit_count.then_some(ctx.per_host_attempts);

    if let Some(subnet) = ctx.subnet_target {
        handle_subnet_scan(
            Subnet::V4(subnet),
            port,
            ctx.udp,
            ctx.timeout,
            rounds,
            ctx.minimal,
            ctx.payload,
        );
        return Ok(());
    }
    if let Some(ipv6_subnet) = ctx.ipv6_subnet_target {
        handle_subnet_scan(
            Subnet::V6(ipv6_subnet),
            port,
            ctx.udp,
            ctx.timeout,
            rounds,
            ctx.minimal,
            ctx.payload,
        );
        return Ok(());
    }

    if ctx.is_multi {
        match port {
            None => handle_multi_icmp(
                ctx.destinations,
                ctx.timeout,
                ctx.per_host_attempts,
                ctx.minimal,
                ctx.payload,
            ),
            Some(p) if ctx.udp => {
                perform_udp_multi_scan(
                    ctx.destinations,
                    p,
                    ctx.timeout,
                    ctx.per_host_attempts,
                    ctx.minimal,
                    ctx.no_asn,
                );
            }
            Some(p) => {
                perform_tcp_multi_scan(
                    ctx.destinations,
                    p,
                    ctx.timeout,
                    ctx.per_host_attempts,
                    ctx.minimal,
                    ctx.no_asn,
                );
            }
        }
    } else {
        handle_single_destination(
            ctx.destination_input,
            port,
            ctx.udp,
            ctx.timeout,
            ctx.count,
            ctx.minimal,
            ctx.no_asn,
            ctx.payload,
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
        ctx.per_host_attempts,
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

#[allow(clippy::struct_excessive_bools)]
struct SimpleFlags {
    minimal: bool,
    http_check: bool,
    no_asn: bool,
    udp: bool,
    dns_server: std::net::SocketAddr,
    payload: &'static [u8; 24],
}

fn parse_simple_flags(args: &Arguments, cfg: Option<&config::Config>) -> SimpleFlags {
    let minimal =
        args.contains(["-m", "--minimal"]) || cfg.and_then(|c| c.minimal).unwrap_or(false);
    let http_check = args.contains(["-s", "--http"]);
    let no_asn = args.contains(["-a", "--no-asn"]) || cfg.and_then(|c| c.no_asn).unwrap_or(false);
    let udp = args.contains(["-u", "--udp"]);
    let dns_server = cfg
        .and_then(|c| c.dns_server)
        .unwrap_or(dns::DEFAULT_DNS_SERVER);
    let payload: &'static [u8; 24] = if cfg.and_then(|c| c.classic_payload).unwrap_or(false) {
        &CLASSIC_ICMP_PAYLOAD
    } else {
        &MEOW_ICMP_PAYLOAD
    };
    SimpleFlags {
        minimal,
        http_check,
        no_asn,
        udp,
        dns_server,
        payload,
    }
}

fn main() -> Result<(), Box<dyn Error>> {
    #[cfg(target_os = "windows")]
    fix_ansicolor::enable_ansi_support();

    colors::init_colors();

    let mut args = Arguments::from_env();

    if args.contains(["-h", "--help"]) {
        output::print_help();
        return Ok(());
    }

    if args.contains(["-V", "--version"]) {
        println!("{} {}", env!("CARGO_PKG_NAME"), env!("CARGO_PKG_VERSION"));
        return Ok(());
    }

    let cfg = load_config(&mut args)?;
    let cfg = cfg.as_ref();

    let SimpleFlags {
        minimal,
        http_check,
        no_asn,
        udp,
        dns_server,
        payload,
    } = parse_simple_flags(&args, cfg);

    let timeout = args
        .opt_value_from_str(["-t", "--timeout"])
        .map_err(|_| "Failed to parse timeout argument")?
        .unwrap_or(1000);
    validate_timeout(timeout).map_err(|e| -> Box<dyn Error> { e.into() })?;

    let (count, explicit_count) = parse_count(&mut args)?;

    let ports: Option<Vec<u16>> = args
        .opt_value_from_str::<String, 2>(["-p", "--port"])
        .map_err(|_| "Failed to parse port argument")?
        .map(|s| parse_ports(&s))
        .transpose()?;

    let destination_input = read_destination(&mut args)?;
    let ResolvedTargets {
        destinations,
        is_multi,
        subnet_target,
        ipv6_subnet_target,
    } = resolve_targets(&destination_input);

    let scan_like = is_multi
        || subnet_target.is_some()
        || ipv6_subnet_target.is_some()
        || ports.as_ref().is_some_and(|p| p.len() > 1);
    let per_host_attempts: usize = compute_per_host_attempts(scan_like, explicit_count, count);

    if !minimal {
        output::print_welcome();
    }

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

    if args.contains(["-d", "--dns"]) {
        if subnet_target.is_some() || ipv6_subnet_target.is_some() {
            return Err("DNS ping is not supported for subnet targets".into());
        }
        if is_multi {
            for domain in &destinations {
                if let Err(e) = perform_dns(domain, timeout, count, minimal, dns_server) {
                    output::print_with_prefix(minimal, &format!("{domain}: {e}").red());
                }
            }
        } else {
            perform_dns(&destination_input, timeout, count, minimal, dns_server)?;
        }
        return Ok(());
    }

    if udp && ports.is_none() {
        return Err("UDP probing requires a port (use -p/--port with --udp)".into());
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
        explicit_count,
        payload,
    };

    run_probe_dispatch(&ctx)?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn compute_per_host_attempts_truth_table() {
        assert_eq!(compute_per_host_attempts(true, false, 65_535), 1);
        assert_eq!(compute_per_host_attempts(false, false, 65_535), 65_535);
        assert_eq!(compute_per_host_attempts(false, false, 10), 10);
        assert_eq!(compute_per_host_attempts(true, true, 7), 7);
        assert_eq!(compute_per_host_attempts(false, true, 7), 7);
    }

    #[test]
    fn zero_timeout_is_rejected() {
        assert!(validate_timeout(0).is_err());
        assert!(validate_timeout(1).is_ok());
        assert!(validate_timeout(1000).is_ok());
    }
}
