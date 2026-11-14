use crate::colors::Colorize;
use crate::output::{PingStats, color_time, micros, print_statistics, print_with_prefix};
use crate::tcp::{fetch_asn, resolve_ip, tcp_connect_once};
use crate::udp::{ProbeOutcome, probe_payload, udp_probe_once};
use std::borrow::Cow;
use std::net::{IpAddr, SocketAddr};
use std::thread;
use std::time::Duration;

const CHUNK: usize = 32;
const RESOLVE_CHUNK: usize = 8;
const ASN_CHUNK: usize = 8;

#[derive(Clone, Copy)]
enum PortVerdict {
    Open { rtt_us: u64 },
    Closed,
    NoResponse,
}

impl PortVerdict {
    /// The round trip of an open port, in microseconds.
    const fn rtt_us(self) -> Option<u64> {
        match self {
            Self::Open { rtt_us } => Some(rtt_us),
            Self::Closed | Self::NoResponse => None,
        }
    }
}

struct PortResult<'a> {
    host: &'a str,
    port: u16,
    verdict: PortVerdict,
}

fn verdict_from_tcp(rtt: Option<Duration>) -> PortVerdict {
    rtt.map_or(PortVerdict::NoResponse, |d| PortVerdict::Open {
        rtt_us: micros(d),
    })
}

fn verdict_from_udp(outcome: ProbeOutcome) -> PortVerdict {
    match outcome {
        ProbeOutcome::Open { rtt, .. } => PortVerdict::Open {
            rtt_us: micros(rtt),
        },
        ProbeOutcome::Closed => PortVerdict::Closed,
        ProbeOutcome::NoResponse => PortVerdict::NoResponse,
    }
}

fn format_port_result(res: &PortResult, asn: &str, udp: bool, minimal: bool) -> String {
    let proto = if udp { "UDP" } else { "TCP" };
    let show_asn = !asn.is_empty();
    let prefix = if minimal {
        String::new()
    } else {
        format!("{} ", "[MEOWPING]".magenta())
    };

    let (paint, detail): (fn(&str) -> String, &str) = match res.verdict {
        PortVerdict::Open { .. } => (<str as Colorize>::green, ""),
        PortVerdict::Closed => (<str as Colorize>::red, " closed (Port Unreachable)"),
        PortVerdict::NoResponse if udp => {
            (<str as Colorize>::orange, " no response (open|filtered)")
        }
        PortVerdict::NoResponse => (<str as Colorize>::red, " timed out"),
    };
    let tail = match (res.verdict, show_asn) {
        (PortVerdict::Open { rtt_us }, true) => {
            format!(" ({}): {}", paint(asn), color_time(rtt_us))
        }
        (PortVerdict::Open { rtt_us }, false) => format!(" {}", color_time(rtt_us)),
        (_, true) => format!("{detail} ({}):", paint(asn)),
        (_, false) => format!("{detail}:"),
    };
    let port = res.port.to_string();
    format!(
        "{prefix}{}:{}{tail} protocol={} port={}",
        paint(res.host),
        paint(&port),
        paint(proto),
        paint(&port)
    )
}

struct ProbeUnit<'a> {
    host: &'a str,
    ip: IpAddr,
    port: u16,
    payload: Cow<'static, [u8]>,
}

fn fan_out<T: Sync, R: Send>(
    items: &[T],
    chunk: usize,
    job: impl Fn(&T) -> R + Sync,
) -> Vec<Option<R>> {
    let mut out = Vec::with_capacity(items.len());
    for part in items.chunks(chunk) {
        thread::scope(|scope| {
            let handles: Vec<_> = part.iter().map(|item| scope.spawn(|| job(item))).collect();
            out.extend(handles.into_iter().map(|h| h.join().ok()));
        });
    }
    out
}

fn probe_units_concurrent(units: &[ProbeUnit], udp: bool, timeout_ms: u64) -> Vec<PortVerdict> {
    let timeout = Duration::from_millis(timeout_ms);
    fan_out(units, CHUNK, |unit| {
        if udp {
            verdict_from_udp(udp_probe_once(
                SocketAddr::new(unit.ip, unit.port),
                &unit.payload,
                timeout,
            ))
        } else {
            verdict_from_tcp(tcp_connect_once(unit.ip, unit.port, timeout_ms))
        }
    })
    .into_iter()
    .map(|verdict| verdict.unwrap_or(PortVerdict::NoResponse))
    .collect()
}

const fn payload_for(port: u16, udp: bool) -> Cow<'static, [u8]> {
    if udp {
        probe_payload(port)
    } else {
        Cow::Borrowed(&[])
    }
}

fn resolve_hosts_concurrent(hosts: &[String], port: u16) -> Vec<Option<IpAddr>> {
    fan_out(hosts, RESOLVE_CHUNK, |host| {
        resolve_ip(host, port).ok().map(|a| a.ip())
    })
    .into_iter()
    .map(Option::flatten)
    .collect()
}

fn fetch_asns_concurrent(ips: &[IpAddr], no_asn: bool, timeout_ms: u64) -> Vec<(IpAddr, String)> {
    let asns = fan_out(ips, ASN_CHUNK, |ip| {
        fetch_asn(&ip.to_string(), no_asn, timeout_ms).unwrap_or_else(|_| "?".to_string())
    });
    ips.iter()
        .zip(asns)
        .filter_map(|(&ip, asn)| Some((ip, asn?)))
        .collect()
}

fn asn_for(asns: &[(IpAddr, String)], ip: IpAddr) -> &str {
    asns.binary_search_by(|(known, _)| known.cmp(&ip))
        .map_or("?", |i| asns[i].1.as_str())
}

fn sorted_unique<T: Ord>(mut items: Vec<T>) -> Vec<T> {
    items.sort_unstable();
    items.dedup();
    items
}

fn print_summary(minimal: bool, summary: &str, proto_label: &str, stats: &PingStats) {
    print_with_prefix(minimal, summary);
    print_statistics(proto_label, stats);
}

fn print_attempt(attempt_idx: usize, attempts: usize, minimal: bool) {
    if !minimal && attempts > 1 {
        let message = format!("Attempt {}/{}", attempt_idx + 1, attempts);
        print_with_prefix(minimal, &message);
    }
}

pub fn perform_host_scan(
    hosts: &[String],
    port: u16,
    udp: bool,
    timeout_ms: u64,
    attempts_per_host: usize,
    minimal: bool,
    no_asn: bool,
) {
    let attempts = attempts_per_host.max(1);
    let resolved: Vec<(&str, Option<IpAddr>)> = hosts
        .iter()
        .map(String::as_str)
        .zip(resolve_hosts_concurrent(hosts, port))
        .collect();
    let asn_by_ip = fetch_asns_concurrent(
        &sorted_unique(resolved.iter().filter_map(|&(_, ip)| ip).collect()),
        no_asn,
        timeout_ms,
    );

    let proto_label = if udp { "UDP multi" } else { "TCP multi" };
    let payload = payload_for(port, udp);

    let mut stats = PingStats::default();
    let mut responsive = vec![false; resolved.len()];

    for attempt_idx in 0..attempts {
        print_attempt(attempt_idx, attempts, minimal);
        for (chunk_idx, chunk) in resolved.chunks(CHUNK).enumerate() {
            let units: Vec<ProbeUnit> = chunk
                .iter()
                .filter_map(|&(host, ip)| {
                    Some(ProbeUnit {
                        host,
                        ip: ip?,
                        port,
                        payload: payload.clone(),
                    })
                })
                .collect();
            let mut verdicts = probe_units_concurrent(&units, udp, timeout_ms).into_iter();
            for (i, &(host, ip)) in chunk.iter().enumerate() {
                let verdict = ip.and_then(|_| verdicts.next());
                let verdict = verdict.unwrap_or(PortVerdict::NoResponse);
                let asn = ip.map_or("resolve error", |ip| asn_for(&asn_by_ip, ip));
                let res = PortResult {
                    host,
                    port,
                    verdict,
                };
                println!("{}", format_port_result(&res, asn, udp, minimal));
                let rtt = verdict.rtt_us();
                stats.record(rtt.is_some(), rtt);
                responsive[chunk_idx * CHUNK + i] |= rtt.is_some();
            }
        }
        if attempt_idx + 1 != attempts {
            thread::sleep(Duration::from_secs(1));
        }
    }

    let responsive_hosts = sorted_unique(
        resolved
            .iter()
            .zip(&responsive)
            .filter(|&(_, &up)| up)
            .map(|(&(host, _), _)| host)
            .collect(),
    );
    if minimal && !responsive_hosts.is_empty() {
        let entries = responsive_hosts
            .iter()
            .map(|h| h.green())
            .collect::<Vec<_>>()
            .join(", ");
        print_with_prefix(minimal, &format!("[{entries}]"));
    }
    let summary = format!(
        "Hosts responsive: {}/{}",
        responsive_hosts.len().to_string().green(),
        hosts.len()
    );
    print_summary(minimal, &summary, proto_label, &stats);
}

fn aggregate(results: &[PortResult], ports: &[u16], minimal: bool, proto_label: &str) {
    let mut stats = PingStats::default();
    let mut responsive_ports: Vec<(&str, u16)> = Vec::new();

    for res in results {
        let rtt = res.verdict.rtt_us();
        stats.record(rtt.is_some(), rtt);
        if rtt.is_some() {
            responsive_ports.push((res.host, res.port));
        }
    }
    let responsive_ports = sorted_unique(responsive_ports);

    if minimal && !responsive_ports.is_empty() {
        let entries = responsive_ports
            .iter()
            .map(|(h, p)| format!("{}:{}", h.green(), p.to_string().green()))
            .collect::<Vec<_>>()
            .join(", ");
        print_with_prefix(minimal, &format!("[{entries}]"));
    }

    let summary = format!(
        "Ports responsive: {}/{} ({} unique ports)",
        responsive_ports.len().to_string().green(),
        stats.attempts(),
        ports.len()
    );
    print_summary(minimal, &summary, proto_label, &stats);
}

fn scan_targets<'a>(
    targets: &'a [(String, IpAddr)],
    ports: &[u16],
    udp: bool,
    timeout_ms: u64,
    attempts: usize,
    minimal: bool,
    asn_by_ip: Option<&[(IpAddr, String)]>,
) -> Vec<PortResult<'a>> {
    let payloads: Vec<_> = ports.iter().map(|&port| payload_for(port, udp)).collect();
    let mut all_results = Vec::with_capacity(targets.len() * ports.len());

    for attempt_idx in 0..attempts {
        print_attempt(attempt_idx, attempts, minimal);

        let mut units = Vec::with_capacity(targets.len() * ports.len());
        for (host, ip) in targets {
            for (&port, payload) in ports.iter().zip(&payloads) {
                units.push(ProbeUnit {
                    host,
                    ip: *ip,
                    port,
                    payload: payload.clone(),
                });
            }
        }

        for chunk in units.chunks(CHUNK) {
            let verdicts = probe_units_concurrent(chunk, udp, timeout_ms);
            for (unit, verdict) in chunk.iter().zip(verdicts) {
                let res = PortResult {
                    host: unit.host,
                    port: unit.port,
                    verdict,
                };
                let open = matches!(verdict, PortVerdict::Open { .. });
                if let Some(asns) = asn_by_ip {
                    println!(
                        "{}",
                        format_port_result(&res, asn_for(asns, unit.ip), udp, minimal)
                    );
                } else if open {
                    println!("{}", format_port_result(&res, "", udp, minimal));
                }
                all_results.push(res);
            }
        }
    }
    all_results
}

pub fn perform_multiport_hosts(
    hosts: &[String],
    ports: &[u16],
    udp: bool,
    timeout_ms: u64,
    attempts: usize,
    minimal: bool,
    no_asn: bool,
) {
    let attempts = attempts.max(1);

    let resolved_all = resolve_hosts_concurrent(hosts, ports[0]);
    let mut resolved: Vec<(String, IpAddr)> = Vec::with_capacity(hosts.len());
    for (host, ip) in hosts.iter().zip(&resolved_all) {
        match ip {
            Some(ip) => {
                if !minimal && ip.to_string() != *host {
                    crate::tcp::print_ip_info(host, &ip.to_string(), minimal);
                }
                resolved.push((host.clone(), *ip));
            }
            None => crate::output::print_resolution_failure(host, minimal),
        }
    }
    if resolved.is_empty() {
        return;
    }

    let asn_by_ip = fetch_asns_concurrent(
        &sorted_unique(resolved_all.iter().copied().flatten().collect()),
        no_asn,
        timeout_ms,
    );

    let proto_label = if udp {
        "UDP multiport"
    } else {
        "TCP multiport"
    };
    let header = format!(
        "Probing {} host(s) x {} port(s) via {}",
        resolved.len(),
        ports.len(),
        if udp { "UDP" } else { "TCP" }
    );
    print_with_prefix(minimal, &header);

    let all_results = scan_targets(
        &resolved,
        ports,
        udp,
        timeout_ms,
        attempts,
        minimal,
        Some(&asn_by_ip),
    );
    aggregate(&all_results, ports, minimal, proto_label);
}

#[expect(
    clippy::too_many_arguments,
    reason = "mirrors the CLI flags one to one, a params struct would only rename them"
)]
pub fn perform_multiport_subnet(
    host_label: &str,
    hosts: &[IpAddr],
    ports: &[u16],
    udp: bool,
    timeout_ms: u64,
    attempts: usize,
    minimal: bool,
    no_asn: bool,
) {
    let attempts = attempts.max(1);
    let Some(first) = hosts.first() else {
        let message = format!("{} has no usable host addresses", host_label.yellow());
        print_with_prefix(minimal, &message);
        return;
    };

    let subnet_asn =
        fetch_asn(&first.to_string(), no_asn, timeout_ms).unwrap_or_else(|_| String::new());

    let proto_label = if udp { "UDP subnet" } else { "TCP subnet" };
    let asn_suffix = if subnet_asn.is_empty() || subnet_asn == "no lookup" {
        String::new()
    } else {
        format!(" [{}]", subnet_asn.green())
    };
    let header = format!(
        "Scanning {} ({} hosts) x {} ports via {}{asn_suffix}",
        host_label.bright_blue(),
        hosts.len(),
        ports.len(),
        if udp { "UDP" } else { "TCP" }
    );
    print_with_prefix(minimal, &header);

    let targets: Vec<(String, IpAddr)> = hosts.iter().map(|&ip| (ip.to_string(), ip)).collect();
    let all_results = scan_targets(&targets, ports, udp, timeout_ms, attempts, minimal, None);
    aggregate(&all_results, ports, minimal, proto_label);
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Instant;

    #[test]
    fn multiport_scan_with_single_attempt_completes_quickly() {
        let hosts: Vec<String> = ["127.0.0.1", "127.0.0.2"]
            .iter()
            .map(ToString::to_string)
            .collect();
        let start = Instant::now();
        perform_multiport_hosts(&hosts, &[1, 2], false, 200, 1, true, true);
        let elapsed = start.elapsed();
        assert!(
            elapsed.as_secs() < 4,
            "multiport scan should complete quickly, took {elapsed:?}"
        );
    }
}
