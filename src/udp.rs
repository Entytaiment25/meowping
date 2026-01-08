use crate::colors::Colorize;
use crate::output::{color_time, print_statistics};
use std::collections::VecDeque;
use std::error::Error;
use std::net::SocketAddr;
use std::thread::sleep;
use std::time::{Duration, Instant};
use std::net::UdpSocket;

use crate::tcp::{resolve_ip, fetch_asn, print_ip_info};

pub fn perform_udp(
    destination: &str,
    port: u16,
    timeout: u64,
    count: usize,
    minimal: bool,
    no_asn: bool,
    interval: u64,
) -> Result<(), Box<dyn Error>> {
    let ip_lookup = resolve_ip(destination, port)?;

    if ip_lookup.ip().to_string() != destination {
        print_ip_info(destination, &ip_lookup.ip().to_string(), minimal);
    }

    let asn = fetch_asn(&ip_lookup.ip().to_string(), no_asn, timeout)?;
    let (successes, times) = perform_connection(ip_lookup, port, timeout, count, &asn, minimal, interval);
    print_statistics("UDP", count, successes, &times);
    Ok(())
}

fn perform_connection(
    ip_lookup: SocketAddr,
    port: u16,
    timeout: u64,
    count: usize,
    asn: &str,
    minimal: bool,
    interval: u64,
) -> (usize, VecDeque<u128>) {
    let mut successes = 0;
    let mut times = VecDeque::new();

    for _ in 0..count {
        let duration = udp_ping_once(ip_lookup, timeout);
        if duration >= 0.0 {
            times.push_back((duration * 1000.0) as u128);
            successes += 1;
        } else {
            times.push_back(0);
        }

        let status_message = format_connection_status(ip_lookup, asn, port, duration, minimal);
        println!("{}", status_message);

        if count > 1 {
            sleep(Duration::from_millis(interval));
        }
    }

    (successes, times)
}

fn udp_ping_once(ip: SocketAddr, timeout: u64) -> f32 {
    let start = Instant::now();
    let socket = UdpSocket::bind("0.0.0.0:0");
    if socket.is_err() {
        return -1.0;
    }
    let socket = socket.unwrap();
    socket.set_read_timeout(Some(Duration::from_millis(timeout))).ok();
    let result = socket.send_to(b"ping", ip);
    let duration = (start.elapsed().as_micros() as f32) / 1000.0;

    if result.is_ok() {
        duration
    } else {
        -1.0
    }
}

fn format_connection_status(
    ip_lookup: SocketAddr,
    asn: &str,
    port: u16,
    duration: f32,
    minimal: bool,
) -> String {
    let show_asn = !minimal || asn != "no lookup";
    let prefix = if minimal {
        String::new()
    } else {
        format!("{} ", "[MEOWPING]".magenta())
    };

    if duration < 0.0 {
        let status_message = if show_asn {
            format!(
                "{} timed out ({}): protocol={} port={}",
                ip_lookup.ip().to_string().red(),
                asn.red(),
                "UDP".red(),
                port.to_string().red()
            )
        } else {
            format!(
                "{} timed out: protocol={} port={}",
                ip_lookup.ip().to_string().red(),
                "UDP".red(),
                port.to_string().red()
            )
        };
        format!("{}{}", prefix, status_message)
    } else {
        let time_colored = color_time(duration as f64);
        let status_message = if show_asn {
            format!(
                "{} ({}): {} protocol={} port={}",
                ip_lookup.ip().to_string().green(),
                asn.green(),
                time_colored,
                "UDP".green(),
                port.to_string().green()
            )
        } else {
            format!(
                "{}: {} protocol={} port={}",
                ip_lookup.ip().to_string().green(),
                time_colored,
                "UDP".green(),
                port.to_string().green()
            )
        };
        format!("{}{}", prefix, status_message)
    }
}