use anyhow::Result;
use pico_args::Arguments;
use std::{ error::Error, net::IpAddr };

mod colors;
mod icmp;
mod tcp;
mod https;
mod parser;
use colors::Colorize;
use icmp::perform_icmp;
use tcp::perform_tcp;
use parser::{ Extracted, Parser };
use https::get_status;

#[cfg(target_os = "windows")]
use colors::fix_ansicolor;

fn check_http_status(url: &str) -> Result<String, Box<dyn Error>> {
    match get_status(url) {
        Ok(status) => Ok(format!("{} is online. HTTP status: {}", url, status)),
        Err(e) => Err(format!("Failed to connect to {}: {}", url, e).into()),
    }
}

fn link<T: Into<String>>(url: T) -> String {
    let url = url.into();

    format!("\u{1b}]8;;{}\u{1b}\\{}\u{1b}]8;;\u{1b}\\", url, url)
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
        println!("{:>30}", "    -h, --help                Prints the Help Menu");
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
        println!("{:>30}", "    -m, --minimal             Changes the Prints to be more Minimal");
        println!(
            "{:>30}",
            "    -s, --http              Check if the destination URL is online via HTTP/S"
        );
        return Ok(());
    }

    let minimal = args.contains(["-m", "--minimal"]);
    let http_check = args.contains(["-s", "--http"]);

    let destination = match args.free_from_str::<String>() {
        Ok(dest) => dest,
        Err(_) => {
            return Err("Destination argument missing".into());
        }
    };

    if http_check {
        match check_http_status(&destination) {
            Ok(status) => {
                println!("{}", status);
                return Ok(());
            }
            Err(e) => {
                eprintln!("Failed to check HTTP status: {}", e);
                return Err(e);
            }
        }
    }

    let timeout = match args.opt_value_from_str(["-t", "--timeout"]) {
        Ok(Some(t)) => t,
        Ok(None) => 1000,
        Err(_) => {
            return Err("Failed to parse timeout argument".into());
        }
    };
    let count = match args.opt_value_from_str(["-c", "--count"]) {
        Ok(Some(c)) => c,
        Ok(None) => 65535,
        Err(_) => {
            return Err("Failed to parse count argument".into());
        }
    };

    let port = args.opt_value_from_str(["-p", "--port"]);

    if !minimal {
        let message = format!(
            "
    ／l、
  （ﾟ､ ｡ ７      welcome to {} ({})!
    l  ~ヽ       {}
    じしf_,)ノ
",
            name,
            link("https://github.com/entytaiment25/meowping"),
            version_format
        ).magenta();

        println!("{}", message);
    }

    let destination = if destination.starts_with('[') && destination.ends_with(']') {
        destination[1..destination.len() - 1].to_string()
    } else if destination.parse::<IpAddr>().is_ok() {
        destination
    } else {
        match Parser::extract_url(&destination) {
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
        Ok(Some(p)) => perform_tcp(&destination, p, timeout, count.into(), minimal)?,
        Ok(None) => {
            let ttl = 64;
            let ident = 0;
            let payload = b"...meow...meow...meow...";
            perform_icmp(&destination, timeout, ttl, ident, count, payload, minimal)?;
        }
        Err(_) => {
            return Err("Failed to parse port argument".into());
        }
    }

    Ok(())
}
