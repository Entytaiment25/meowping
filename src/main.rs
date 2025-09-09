use std::thread::sleep;
use std::time::Duration;
use std::{error::Error, net::IpAddr};

mod cli;
mod colors;
mod https;
mod icmp;
mod parser;
mod tcp;

use cli::Arguments;
use colors::{Colorize, HyperLink};
use icmp::perform_icmp;
use parser::{Extracted, Parser};
use tcp::perform_tcp;

#[cfg(target_os = "windows")]
use colors::fix_ansicolor;

fn check_http_status(url: &str, minimal: bool, timeout: u64) -> Result<String, Box<dyn Error>> {
    match https::get_status(url, timeout) {
        Ok(status) => {
            let message = format!("{} is online. HTTP status: {}", url, status);
            if minimal {
                Ok(message)
            } else {
                Ok(format!("{} {}", "[MEOWPING]".magenta(), message))
            }
        }
        Err(e) => {
            let error_msg = if minimal {
                e.to_string()
            } else {
                format!("{} {}", "[MEOWPING]".magenta(), e)
            };
            Err(error_msg.into())
        }
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
        return Ok(());
    }

    let minimal = args.contains(["-m", "--minimal"]);

    let destination = match args.free_from_str::<String>() {
        Ok(dest) => dest,
        Err(_) => {
            return Err("Destination argument missing".into());
        }
    };

    let http_check = args.contains(["-s", "--http"]);

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

    if http_check {
        let mut url = destination.clone();
        if !url.starts_with("http://") && !url.starts_with("https://") {
            url = format!("http://{}", url);
        }
        for i in 0..count {
            match check_http_status(&url, minimal, timeout) {
                Ok(status) => {
                    println!("{}", status);
                }
                Err(e) => {
                    println!("{}", e);
                }
            }
            if i < count - 1 {
                sleep(Duration::from_secs(1));
            }
        }
        return Ok(());
    }

    let port = args.opt_value_from_str(["-p", "--port"]);

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
            let ident: u16 = 0;
            let payload: [u8; 24] = [
                46, 46, 46, 109, 101, 111, 119, 46, 46, 46, 109, 101, 111, 119, 46, 46, 46, 109,
                101, 111, 119, 46, 46, 46,
            ];
            perform_icmp(&destination, timeout, ttl, ident, count, &payload, minimal)?;
        }
        Err(_) => {
            return Err("Failed to parse port argument".into());
        }
    }

    Ok(())
}
