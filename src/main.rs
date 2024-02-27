use clap::{ Arg, ArgMatches, Command };
use json::parse;
use std::collections::VecDeque;
use std::net::{ SocketAddr, TcpStream, ToSocketAddrs };
use std::thread::sleep;
use std::time::{ Duration, Instant };

mod colors;
use colors::Colorize;

#[cfg(target_os = "windows")]
use colors::fix_ansicolor;

fn get_arg<T: AsRef<str>>(matches: &ArgMatches, key: T) -> Option<&str> {
    matches.get_one::<String>(key.as_ref()).map(|s| s.as_str())
}

fn link<T: Into<String>>(url: T) -> String {
    let url = url.into();

    format!("\u{1b}]8;;{}\u{1b}\\{}\u{1b}]8;;\u{1b}\\", url, url)
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    #[cfg(target_os = "windows")]
    fix_ansicolor::enable_ansi_support();
    let version = env!("CARGO_PKG_VERSION");
    let version_format = format!("v.{}", env!("CARGO_PKG_VERSION"));
    let name = env!("CARGO_PKG_NAME");
    let description = env!("CARGO_PKG_DESCRIPTION");

    let matches = Command::new(name)
        .version(version)
        .about(description)
        .arg(Arg::new("destination").required(true).index(1))
        .arg(Arg::new("port").short('p').long("port").required(true))
        .arg(Arg::new("timeout").short('t').long("timeout").default_value("1000"))
        .arg(Arg::new("count").short('c').long("count").default_value("99999"))
        .get_matches();

    let destination = get_arg(&matches, "destination").unwrap();
    let port = get_arg(&matches, "port").unwrap().parse::<u16>().expect("Invalid port number");
    let timeout = get_arg(&matches, "timeout")
        .unwrap()
        .parse::<u64>()
        .expect("Invalid timeout value");
    let count = get_arg(&matches, "count").unwrap().parse::<usize>().expect("Invalid count value");

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

    let destination = if destination.starts_with("https://") {
        if destination.ends_with('/') {
            destination.strip_prefix("https://").unwrap().strip_suffix('/').unwrap()
        } else {
            destination.strip_prefix("https://").unwrap()
        }
    } else if destination.starts_with("http://") {
        if destination.ends_with('/') {
            destination.strip_prefix("http://").unwrap().strip_suffix('/').unwrap()
        } else {
            destination.strip_prefix("http://").unwrap()
        }
    } else {
        destination
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
    let response = ureq::get(&url).call()?.into_string()?;
    let parsed_json = parse(&response)?;
    let asn = parsed_json["as"].to_string();

    let mut times = VecDeque::new();
    let mut successes = 0;

    for _ in 0..count {
        let start = Instant::now();

        let connect_result = TcpStream::connect_timeout(
            &SocketAddr::new(ip_lookup.ip(), port),
            Duration::from_millis(timeout)
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
    let avg_time =
        (
            (if successes > 0 {
                times.iter().sum::<u128>() / (successes as u128)
            } else {
                0
            }) as f32
        ) / 1000.0;

    Ok({
        println!("\nConnection statistics:");
        println!(
            "        Attempted = {}, Connected = {}, Failed = {} ({} loss)",
            attempted.to_string().blue(),
            successes.to_string().blue(),
            failed.to_string().blue(),
            format!("{:.2}%", ((failed as f32) / (attempted as f32)) * 100.0).blue()
        );
        println!("Approximate connection times:");
        println!(
            "        Minimum = {}, Maximum = {}, Average = {}",
            format!("{:.2}ms", min_time).blue(),
            format!("{:.2}ms", max_time).blue(),
            format!("{:.2}ms", avg_time).blue()
        );
    })
}
