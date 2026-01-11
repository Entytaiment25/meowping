use crate::colors::{Colorize, HyperLink};
use std::collections::VecDeque;

pub fn print_with_prefix(minimal: bool, message: String) {
    if minimal {
        println!("{}", message);
    } else {
        println!("{} {}", "[MEOWPING]".magenta(), message);
    }
}

pub fn print_statistics(protocol: &str, count: usize, successes: usize, times: &VecDeque<u128>) {
    let failed = count - successes;

    let good_times: Vec<u128> = times.iter().copied().filter(|&t| t > 0).collect();

    let (min_time, max_time, avg_time) = if !good_times.is_empty() {
        let min = (*good_times.iter().min().unwrap() as f32) / 1000.0;
        let max = (*good_times.iter().max().unwrap() as f32) / 1000.0;
        let avg = (good_times.iter().sum::<u128>() as f32) / (good_times.len() as f32) / 1000.0;
        (min, max, avg)
    } else {
        (0.0, 0.0, 0.0)
    };

    let loss_percentage = if count > 0 {
        ((failed as f32) / (count as f32)) * 100.0
    } else {
        0.0
    };

    println!("\n{} Ping statistics:", protocol);
    println!(
        "\tAttempted = {}, Successes = {}, Failures = {} ({} loss)",
        count.to_string().bright_blue(),
        successes.to_string().bright_blue(),
        failed.to_string().bright_blue(),
        format!("{:.2}%", loss_percentage).bright_blue()
    );
    println!("Approximate round trip times:");
    println!(
        "\tMinimum = {}, Maximum = {}, Average = {}",
        format!("{:.2}ms", min_time).bright_blue(),
        format!("{:.2}ms", max_time).bright_blue(),
        format!("{:.2}ms", avg_time).bright_blue()
    );
}

pub fn color_time(time_ms: f64) -> String {
    let msg = format!("{:.2}ms", time_ms);
    match time_ms {
        t if t >= 250.0 => msg.orange(),
        t if t >= 100.0 => msg.yellow(),
        _ => msg.green(),
    }
}

pub fn print_help() {
    let name = env!("CARGO_PKG_NAME");
    println!(
        "{} - A flexible ping utility Tool written in Rust, that is focused on being size efficient and fast.",
        name
    );
    println!(
        "\n{}: {} <destination> [options]",
        "Usage".bright_blue(),
        name
    );
    println!("\n{}:", "Options".bright_blue());
    println!("    -h, --help                Prints the Help Menu");
    println!("    -p, --port <port>         Set the port number (default: ICMP, with: TCP)");
    println!(
        "    -t, --timeout <timeout>   Set the timeout for each connection attempt in milliseconds (default: 1000ms)"
    );
    println!(
        "    -c, --count <count>       Set the number of connection attempts (default: 65535)"
    );
    println!("    -m, --minimal             Changes the Prints to be more Minimal");
    println!("    -s, --http              Check if the destination URL is online via HTTP/S");
    println!("    -a, --no-asn            Disable ASN/organization lookups (use static data)");

    println!("\n{}", "Examples:".bright_blue());

    println!("\n  {}:", "Single Host Ping".yellow());
    println!("    {} google.com", name);
    println!("    {} 8.8.8.8 -c 10", name);
    println!("    {} 2606:4700:4700::1111", name);

    println!("\n  {}:", "TCP Port Check".yellow());
    println!("    {} example.com -p 443", name);
    println!("    {} 192.168.1.1 -p 22 -t 2000", name);

    println!("\n  {}:", "HTTP/HTTPS Check".yellow());
    println!("    {} https://example.com -s", name);
    println!("    {} example.com -s -c 5", name);

    println!("\n  {}:", "Multi-Ping (Multiple Destinations)".yellow());
    println!("    {} google.com,cloudflare.com,1.1.1.1 -c 2", name);
    println!("    {} \"8.8.8.8,1.1.1.1,9.9.9.9\" -c 10", name);

    println!("\n  {}:", "Subnet Scanning".yellow());
    println!("    {} 192.168.1.0/24", name);
    println!("    {} 10.0.0.0/28 -c 3", name);
    println!("    {} 192.168.1.0/24 -p 80", name);
    println!("    {} 2001:db8::/120", name);
    println!("    {} fe80::/112 -p 22", name);

    println!("\n{}:", "IPv6 Support".bright_blue());
    println!("    MeowPing supports IPv6 addresses for all connection types (ICMP, TCP, HTTP)");
    println!("    IPv6 subnet scanning is supported up to /112 prefix length");

    println!("\n{}:", "Notes".bright_blue());
    println!("    • Subnet scans default to 1 attempt per host unless -c is specified");
    println!("    • Multi-ping supports mixing hostnames and IP addresses");
    println!("    • ICMP may require elevated privileges on some systems");
}

pub fn print_welcome() {
    let version_format = format!("v.{}", env!("CARGO_PKG_VERSION"));
    let name = env!("CARGO_PKG_NAME");
    let hyperlink =
        HyperLink::new(name, "https://github.com/entytaiment25/meowping").expect("valid hyperlink");
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
