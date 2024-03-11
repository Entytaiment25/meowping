use json::parse;
use pico_args::Arguments;
use std::collections::VecDeque;
use std::error::Error;
use std::net::{SocketAddr, TcpStream, ToSocketAddrs};
use std::thread::sleep;
use std::time::{Duration, Instant};

mod colors;
mod parser;
use colors::Colorize;
use parser::extract_url;

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
        println!("Options:");
        println!("    -h, --help         Print this help menu");
        println!("    -p, --port <port>  Set the port number (required)");
        println!("    -t, --timeout <timeout>  Set the timeout value (default: 1000)");
        println!("    -c, --count <count>  Set the count value (default: 99999)");

        return Ok(());
    }

    let destination = args.free_from_str::<String>().unwrap();
    let port = args
        .opt_value_from_str(["-p", "--port"])
        .unwrap()
        .expect("Port number is required");
    let timeout = args
        .opt_value_from_str(["-t", "--timeout"])
        .unwrap()
        .unwrap_or(1000);
    let count = args
        .opt_value_from_str(["-c", "--count"])
        .unwrap()
        .unwrap_or(99999);

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
    )
    .magenta();

    println!("{}", message);

    let destination = match extract_url(&destination) {
        Extracted::Error() => {
            println!(
                "{} {}",
                "[MEOWPING]".magenta(),
                "DNS Lookup of domain failed :(",
            );

            return Ok(());
        }
        Extracted::Success(host) => host,
    };

    let with_port = format!("{}:{}", destination, port);
    let ip_lookup = with_port
        .to_socket_addrs()
        .expect("Unable to find ip address from domain using default dns-lookup.")
        .next()
        .expect("Unable to find ip address from domain using default dns-lookup.");

    if ip_lookup.ip().to_string() != destination {
        println!(
            "{} {}",
            "[MEOWPING]".magenta(),
            format!(
                "Found ip address of domain {}: {}",
                destination.green(),
                ip_lookup.ip().to_string().green()
            )
        );
    }

    // get asn
    let url = format!("http://ip-api.com/json/{}?fields=2048", ip_lookup.ip());
    let response = attohttpc::get(&url).send()?.text()?;
    let parsed_json = parse(&response)?;
    let asn = parsed_json["as"].to_string();

    let mut times = VecDeque::new();
    let mut successes = 0;

    for _ in 0..count {
        let start = Instant::now();

        let connect_result = TcpStream::connect_timeout(
            &SocketAddr::new(ip_lookup.ip(), port),
            Duration::from_millis(timeout),
        );

        let duration = start.elapsed().as_micros();
        times.push_back(duration);
        successes += 1;

        let duration = (duration as f32) / 1000.0;
        match connect_result {
            Ok(_) => {
                println!(
                    "{} Connected to {} ({}): time={} protocol={} port={}",
                    "[MEOWPING]".magenta(),
                    destination.green(),
                    asn.green(),
                    format!("{:.2}ms", duration).green(),
                    "TCP".green(),
                    port.to_string().green()
                );

                sleep(Duration::from_secs(1));
            }
            Err(_) => {
                println!(
                    "{} Connection to {} timed out ({}): time={} protocol={} port={}",
                    "[MEOWPING]".magenta(),
                    destination.red(),
                    asn.red(),
                    format!("{:.2}ms", duration).red(),
                    "TCP".red(),
                    port.to_string().red()
                );
            }
        }
    }

    let attempted = count;
    let failed = attempted - successes;
    let min_time = (*times.iter().min().unwrap_or(&0) as f32) / 1000.0;
    let max_time = (*times.iter().max().unwrap_or(&0) as f32) / 1000.0;
    let avg_time = ((if successes > 0 {
        times.iter().sum::<u128>() / (successes as u128)
    } else {
        0
    }) as f32)
        / 1000.0;

    Ok({
        println!("\nConnection statistics:");
        println!(
            "\tAttempted = {}, Connected = {}, Failed = {} ({} loss)",
            attempted.to_string().blue(),
            successes.to_string().blue(),
            failed.to_string().blue(),
            format!("{:.2}%", ((failed as f32) / (attempted as f32)) * 100.0).blue()
        );
        println!("Approximate connection times:");
        println!(
            "\tMinimum = {}, Maximum = {}, Average = {}",
            format!("{:.2}ms", min_time).blue(),
            format!("{:.2}ms", max_time).blue(),
            format!("{:.2}ms", avg_time).blue()
        );
    })
}
