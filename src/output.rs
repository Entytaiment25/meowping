use crate::colors::{Colorize, HyperLink};
use std::time::Duration;

#[derive(Default)]
pub struct PingStats {
    attempts: usize,
    successes: usize,
    min_us: Option<u128>,
    max_us: u128,
    sum_us: u128,
}

impl PingStats {
    pub fn record(&mut self, success: bool, rtt: Option<u128>) {
        self.attempts = self.attempts.saturating_add(1);
        if success {
            self.successes += 1;
        }
        if let Some(us) = rtt {
            self.min_us = Some(self.min_us.map_or(us, |m| m.min(us)));
            self.max_us = self.max_us.max(us);
            self.sum_us = self.sum_us.saturating_add(us);
        }
    }

    pub const fn attempts(&self) -> usize {
        self.attempts
    }

    pub const fn successes(&self) -> usize {
        self.successes
    }
}

pub fn format_with_prefix(minimal: bool, message: &str) -> String {
    if minimal {
        message.to_string()
    } else {
        format!("{} {}", "[MEOWPING]".magenta(), message)
    }
}

pub fn print_with_prefix(minimal: bool, message: &str) {
    println!("{}", format_with_prefix(minimal, message));
}

pub fn print_resolution_failure(host: &str, minimal: bool) {
    let message = format!("DNS Lookup of domain failed: Invalid host or URL: {host}");
    print_with_prefix(minimal, &message);
}

pub fn micros_to_ms(micros: u128) -> f64 {
    Duration::from_micros(u64::try_from(micros).unwrap_or(u64::MAX)).as_secs_f64() * 1000.0
}

pub fn print_statistics(protocol: &str, stats: &PingStats) {
    let count = stats.attempts();
    let successes = stats.successes();
    let failed = count.saturating_sub(successes);

    let (min_time, max_time, avg_time) = if successes == 0 {
        (0.0, 0.0, 0.0)
    } else {
        let min = micros_to_ms(stats.min_us.unwrap_or(0));
        let max = micros_to_ms(stats.max_us);
        let sample_count = f64::from(u32::try_from(successes).unwrap_or(u32::MAX));
        let avg = micros_to_ms(stats.sum_us) / sample_count;
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
    println!("    -V, --version             Prints the version");
    println!(
        "    -p, --port <port(s)>      Port to probe (default: ICMP). Accepts a single port, a comma list (53,80,443), or a range (20-25)"
    );
    println!(
        "    -t, --timeout <timeout>   Set the timeout for each connection attempt in milliseconds (default: 1000ms, minimum: 1ms)"
    );
    println!(
        "    -c, --count <count>       Set the number of connection attempts (default: 65535)"
    );
    println!("    -m, --minimal             Changes the Prints to be more Minimal");
    println!("    -s, --http                Check if the destination URL is online via HTTP/S");
    println!("    -u, --udp                 Probe a UDP port instead of using TCP (requires -p)");
    println!(
        "    -d, --dns                 DNS ping: time A record lookups for the destination (resolver: dns_server in config, default 1.1.1.1)"
    );
    println!("    -a, --no-asn              Disable ASN/organization lookups (use static data)");
    println!(
        "    -C, --config [path]       Load settings from a config file (default: meowping.conf next to the executable)"
    );

    println!("\n{}", "Examples:".bright_blue());

    println!("\n  {}:", "Single Host Ping".yellow());
    println!("    {name} google.com");
    println!("    {name} 8.8.8.8 -c 10");
    println!("    {name} 2606:4700:4700::1111");

    println!("\n  {}:", "TCP Port Check".yellow());
    println!("    {name} example.com -p 443");
    println!("    {name} 192.168.1.1 -p 22 -t 2000");

    println!("\n  {}:", "UDP Port Probe".yellow());
    println!("    {name} 1.1.1.1 -p 53 -u");
    println!("    {name} time.google.com -p 123 -u -c 3");

    println!("\n  {}:", "Multi-Port Probe".yellow());
    println!("    {name} 1.1.1.1 -p 53,80,443");
    println!("    {name} example.com -p 22,80,443,8080");
    println!("    {name} 192.168.1.1 -p 20-25");
    println!("    {name} 1.1.1.1 -p 53,80,443 -u");
    println!("    {name} 192.168.1.0/28 -p 80,443");

    println!("\n  {}:", "DNS Ping".yellow());
    println!("    {name} google.com -d");
    println!("    {name} google.com,cloudflare.com -d -c 5");

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
    println!(
        "    • Subnet scans continuously re-probe and live-update host statuses (Ctrl+C to stop) unless -c is specified"
    );
    println!("    • Multi-ping supports mixing hostnames and IP addresses");
    println!("    • ICMP may require elevated privileges on some systems");
    println!(
        "    • UDP probes need no privileges: a response means open, 'Port Unreachable' means closed, and silence is reported as open|filtered"
    );
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
