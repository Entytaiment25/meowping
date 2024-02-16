use clap::{ Arg, ArgAction, Command };
use std::collections::VecDeque;
use std::net::{ SocketAddr, TcpStream };
use std::thread::sleep;
use std::time::{ Duration, Instant };

mod colors;
use colors::Colorize;

fn main() {
    let version = env!("CARGO_PKG_VERSION");
    let version_format = format!("v.{}", env!("CARGO_PKG_VERSION"));
    let name: &str = &env!("CARGO_PKG_NAME");
    let description: &str = &env!("CARGO_PKG_DESCRIPTION");

    let matches = Command::new(name)
        .version(version)
        .about(description)
        .arg(Arg::new("destination").required(true).index(1))
        .arg(Arg::new("port").short('p').long("port").required(true))
        .arg(Arg::new("timeout").short('t').long("timeout"))
        .arg(Arg::new("count").short('c').long("count"))
        .arg(Arg::new("nocolor").short('n').long("nocolor").action(ArgAction::SetTrue))
        .get_matches();

    let destination = matches
        .get_one::<String>("destination")
        .map(|s| s.as_str())
        .unwrap();
    let port = matches
        .get_one::<String>("port")
        .map(|s| s.as_str())
        .unwrap()
        .parse::<u16>()
        .expect("Invalid port number");
    let timeout = matches
        .get_one::<String>("timeout")
        .map(|s| s.as_str())
        .unwrap_or("1000")
        .parse::<u64>()
        .expect("Invalid timeout value");
    let count = matches
        .get_one::<String>("count")
        .map(|s| s.as_str())
        .unwrap_or("4")
        .parse::<i32>()
        .expect("Invalid count value");
    let nocolor = matches.get_flag("nocolor");

    if !nocolor {
        println!("{}", "  ／l、             ".magenta());
        println!("{}", format!("（ﾟ､ ｡ ７      welcome to {}!   ", name).magenta());
        println!("{}", format!("  l  ~ヽ        {}   ", version_format).magenta());
        println!("{}", "  じしf_,)ノ        \n".magenta());
    } else {
        println!("  ／l、             ");
        println!("（ﾟ､ ｡ ７      welcome to {}!   ", name);
        println!("  l  ~ヽ        {}   ", version_format);
        println!("  じしf_,)ノ        \n");
    }

    let protocol_port = format!("TCP {}", port).yellow();

    if !nocolor {
        println!("Connecting to {} on {}:", destination.yellow(), protocol_port);
    } else {
        println!("Connecting to {} on TCP {}:", destination, port);
    }

    let mut times = VecDeque::new();
    let mut successes = 0;

    for _ in 0..count {
        let start = Instant::now();
        match
            TcpStream::connect_timeout(
                &SocketAddr::new(destination.parse().expect("Invalid destination address"), port),
                Duration::from_millis(timeout)
            )
        {
            Ok(_) => {
                let duration = start.elapsed().as_millis();
                times.push_back(duration);
                successes += 1;
                if !nocolor {
                    println!(
                        "Connected to {}: time={} protocol={} port={}",
                        destination.green(),
                        format!("{}ms", duration).green(),
                        "TCP".green(),
                        port.to_string().green()
                    );
                } else {
                    println!(
                        "Connected to {}: time={} protocol=TCP port={}",
                        destination,
                        duration,
                        port
                    );
                }
                sleep(Duration::from_secs(1));
            }
            Err(e) => {
                if !nocolor {
                    println!(
                        "Connection to {} failed: {}",
                        destination.yellow(),
                        e.to_string().red()
                    );
                } else {
                    println!("Connection to {} failed: {}", destination, e);
                }
            }
        }
    }

    let attempted = count;
    let failed = attempted - successes;
    let min_time = times.iter().min().unwrap_or(&0);
    let max_time = times.iter().max().unwrap_or(&0);
    let avg_time = if successes > 0 { times.iter().sum::<u128>() / (successes as u128) } else { 0 };

    if !nocolor {
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
            format!("{}ms", min_time).blue(),
            format!("{}ms", max_time).blue(),
            format!("{}ms", avg_time).blue()
        );
    } else {
        println!("\nConnection statistics:");
        println!(
            "        Attempted = {}, Connected = {}, Failed = {} ({}% loss)",
            attempted,
            successes,
            failed,
            ((failed as f32) / (attempted as f32)) * 100.0
        );
        println!("Approximate connection times:");
        println!(
            "        Minimum = {}ms, Maximum = {}ms, Average = {}ms",
            min_time,
            max_time,
            avg_time
        );
    }
}
