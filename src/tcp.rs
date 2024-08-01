use std::collections::VecDeque;
use std::net::{ SocketAddr, TcpStream, ToSocketAddrs };
use std::time::{ Duration, Instant };
use std::thread::sleep;
use anyhow::Result;
use minreq;
use jzon::JsonValue;
use crate::colors::Colorize;

pub fn perform_tcp(destination: &str, port: u16, timeout: u64, count: usize) -> Result<()> {
    let with_port = format!("{}:{}", destination, port);
    let ip_lookup = with_port
        .to_socket_addrs()?
        .next()
        .expect("Unable to find IP address from domain using default DNS lookup.");

    if ip_lookup.ip().to_string() != destination {
        println!(
            "{} {}",
            "[MEOWPING]".magenta(),
            format!(
                "Found IP address of domain {}: {}",
                destination.green(),
                ip_lookup.ip().to_string().green()
            )
        );
    }

    // Get ASN
    let url = format!("https://ipinfo.io/{}/json", ip_lookup.ip());
    let response = minreq::get(&url).send()?;
    let response_text = response.as_str()?;
    let parsed_json: JsonValue = jzon::parse(&response_text)?;
    let asn = parsed_json["org"].as_str().unwrap_or("ASN not found").to_string();

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
                sleep(Duration::from_secs(1));
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

    println!("\nConnection statistics:");
    println!(
        "\tAttempted = {}, Connected = {}, Failed = {} ({}% loss)",
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

    Ok(())
}
