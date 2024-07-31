use anyhow::Result;
use pico_args::Arguments;
use std::error::Error;

mod colors;
mod icmp;
mod parser;
mod tcp;
use colors::Colorize;
use icmp::perform_icmp;
use parser::extract_url;
use tcp::perform_tcp;

#[cfg(target_os = "windows")]
use colors::fix_ansicolor;

use crate::parser::Extracted;

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
        println!("Usage: {} [options] <destination>", name);
        println!();
        println!("Optional Options:");
        println!("    -h, --help         Print this help menu");
        println!("    -p, --port <port>  Set the port number (default: ICMP, with: TCP)");
        println!("    -t, --timeout <timeout>  Set the timeout value (default: 1000)");
        println!("    -c, --count <count>  Set the count value (default: 65535)");
        println!("    -m, --minimal      Enable minimal output mode");
        return Ok(());
    }

    let minimal = args.contains(["-m", "--minimal"]);

    let destination = match args.free_from_str::<String>() {
        Ok(dest) => dest,
        Err(_) => {
            return Err("Destination argument missing".into());
        }
    };
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

    let destination = match extract_url(&destination) {
        Extracted::Error() => {
            if !minimal {
                println!(
                    "{} {}",
                    "[MEOWPING]".magenta(),
                    "DNS Lookup of domain failed: Invalid host or URL"
                );
            }
            return Ok(());
        }
        Extracted::Success(host) => host,
    };

    match port {
        Ok(Some(p)) => perform_tcp(&destination, p, timeout, count.into())?,
        Ok(None) => {
            let ttl = 64;
            let ident = 0;
            let custom_payload = b"...meow...meow...meow..."; // 24-byte custom payload
            perform_icmp(&destination, timeout, ttl, ident, count, custom_payload)?;
        }
        Err(_) => {
            return Err("Failed to parse port argument".into());
        }
    }

    Ok(())
}
