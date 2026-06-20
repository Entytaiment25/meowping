use crate::colors::{Colorize, HyperLink};
use std::collections::VecDeque;
use std::time::Duration;

pub fn print_with_prefix(minimal: bool, message: &str) {
    if minimal {
        println!("{message}");
    } else {
        println!("{} {}", "[MEOWPING]".magenta(), message);
    }
}

pub fn micros_to_ms(micros: u128) -> f64 {
    Duration::from_micros(u64::try_from(micros).unwrap_or(u64::MAX)).as_secs_f64() * 1000.0
}

pub fn print_statistics(protocol: &str, count: usize, successes: usize, times: &VecDeque<u128>) {
    let failed = count - successes;

    let good_times: Vec<u128> = times.iter().copied().filter(|&t| t > 0).collect();

    let (min_time, max_time, avg_time) = if good_times.is_empty() {
        (0.0, 0.0, 0.0)
    } else {
        let min = good_times.iter().copied().min().map_or(0.0, micros_to_ms);
        let max = good_times.iter().copied().max().map_or(0.0, micros_to_ms);
        let total_ms: f64 = good_times.iter().copied().map(micros_to_ms).sum();
        let sample_count = f64::from(u32::try_from(good_times.len()).unwrap_or(u32::MAX));
        let avg = total_ms / sample_count;
        (min, max, avg)
    };

    let loss_percentage = if count > 0 {
        let failed_count = f64::from(u32::try_from(failed).unwrap_or(u32::MAX));
        let total_count = f64::from(u32::try_from(count).unwrap_or(u32::MAX));
        (failed_count / total_count) * 100.0
    } else {
        0.0
    };

    println!("\n{protocol} Ping statistics:");
    println!(
        "\tAttempted = {}, Successes = {}, Failures = {} ({} loss)",
        count.to_string().bright_blue(),
        successes.to_string().bright_blue(),
        failed.to_string().bright_blue(),
        format!("{loss_percentage:.2}%").bright_blue()
    );
    println!("Approximate round trip times:");
    println!(
        "\tMinimum = {}, Maximum = {}, Average = {}",
        format!("{min_time:.2}ms").bright_blue(),
        format!("{max_time:.2}ms").bright_blue(),
        format!("{avg_time:.2}ms").bright_blue()
    );
}

pub fn color_time(time_ms: f64) -> String {
    let msg = format!("{time_ms:.2}ms");
    match time_ms {
        t if t >= 250.0 => msg.orange(),
        t if t >= 100.0 => msg.yellow(),
        _ => msg.green(),
    }
}

pub fn print_help() {
    let name = env!("CARGO_PKG_NAME");
    let version = env!("CARGO_PKG_VERSION").bright_blue();
    println!(
        "{name} {version} - A flexible ping utility Tool written in Rust, that is focused on being size efficient and fast."
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
    println!(
        "    -C, --config [path]     Load settings from a config file (default: meowping.conf next to the executable)"
    );

    println!("\n{}", "Examples:".bright_blue());

    println!("\n  {}:", "Single Host Ping".yellow());
    println!("    {name} google.com");
    println!("    {name} 8.8.8.8 -c 10");
    println!("    {name} 2606:4700:4700::1111");

    println!("\n  {}:", "TCP Port Check".yellow());
    println!("    {name} example.com -p 443");
    println!("    {name} 192.168.1.1 -p 22 -t 2000");

    println!("\n  {}:", "HTTP/HTTPS Check".yellow());
    println!("    {name} https://example.com -s");
    println!("    {name} example.com -s -c 5");

    println!("\n  {}:", "Multi-Ping (Multiple Destinations)".yellow());
    println!("    {name} google.com,cloudflare.com,1.1.1.1 -c 2");
    println!("    {name} \"8.8.8.8,1.1.1.1,9.9.9.9\" -c 10");

    println!("\n  {}:", "Subnet Scanning".yellow());
    println!("    {name} 192.168.1.0/24");
    println!("    {name} 10.0.0.0/28 -c 3");
    println!("    {name} 192.168.1.0/24 -p 80");
    println!("    {name} 2001:db8::/120");
    println!("    {name} fe80::/112 -p 22");

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
  （ﾟ､ ｡ ７      welcome to {hyperlink}!
    l  ~ヽ       {version_format}
    じしf_,)ノ
"
    )
    .magenta();
    println!("{message}");
}
