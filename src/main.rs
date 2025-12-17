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

    let subnet_target = Ipv4Subnet::from_str(&destination_input).ok();

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
        let mut url = destination_input.clone();
        if !url.starts_with("http://") && !url.starts_with("https://") {
            url = format!("http://{}", url);
        }
        return perform_http_check(&url, timeout, count, minimal);
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

    let destination = if destination_input.starts_with('[') && destination_input.ends_with(']') {
        destination_input[1..destination_input.len() - 1].to_string()
    } else if destination_input.parse::<IpAddr>().is_ok() {
        destination_input
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

    Ok(())
}
