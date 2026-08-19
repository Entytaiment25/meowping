use crate::colors::Colorize;
use crate::output::{PingStats, color_time, micros_to_ms, print_statistics, print_with_prefix};
use crate::tcp::{fetch_asn, resolve_ip, tcp_connect_once};
use crate::udp::{ProbeOutcome, probe_payload, udp_probe_once};
use std::borrow::Cow;
use std::collections::{HashMap, HashSet};
use std::net::{IpAddr, SocketAddr};
use std::thread;
use std::time::Duration;

const CHUNK: usize = 32;
const RESOLVE_CHUNK: usize = 8;
const ASN_CHUNK: usize = 8;

#[derive(Clone, Copy)]
enum PortVerdict {
    Open { rtt_us: u128 },
    Closed,
    NoResponse,
}

struct PortResult {
    host: String,
    port: u16,
    verdict: PortVerdict,
}

fn verdict_from_tcp(rtt: Option<Duration>) -> PortVerdict {
    rtt.map_or(PortVerdict::NoResponse, |d| PortVerdict::Open {
        rtt_us: d.as_micros(),
    })
}

const fn verdict_from_udp(outcome: ProbeOutcome) -> PortVerdict {
    match outcome {
        ProbeOutcome::Open { rtt, .. } => PortVerdict::Open {
            rtt_us: rtt.as_micros(),
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

    let body = match res.verdict {
        PortVerdict::Open { rtt_us } => {
            let time_colored = color_time(micros_to_ms(rtt_us));
            if show_asn {
                format!(
                    "{}:{} ({}): {} protocol={} port={}",
                    res.host.green(),
                    res.port.to_string().green(),
                    asn.green(),
                    time_colored,
                    proto.green(),
                    res.port.to_string().green()
                )
            } else {
                format!(
                    "{}:{} {} protocol={} port={}",
                    res.host.green(),
                    res.port.to_string().green(),
                    time_colored,
                    proto.green(),
                    res.port.to_string().green()
                )
            }
        }
        PortVerdict::Closed => {
            if show_asn {
                format!(
                    "{}:{} closed (Port Unreachable) ({}): protocol={} port={}",
                    res.host.red(),
                    res.port.to_string().red(),
                    asn.red(),
                    proto.red(),
                    res.port.to_string().red()
                )
            } else {
                format!(
                    "{}:{} closed (Port Unreachable): protocol={} port={}",
                    res.host.red(),
                    res.port.to_string().red(),
                    proto.red(),
                    res.port.to_string().red()
                )
            }
        }
        PortVerdict::NoResponse => {
            if udp {
                if show_asn {
                    format!(
                        "{}:{} no response (open|filtered) ({}): protocol={} port={}",
                        res.host.orange(),
                        res.port.to_string().orange(),
                        asn.orange(),
                        proto.orange(),
                        res.port.to_string().orange()
                    )
                } else {
                    format!(
                        "{}:{} no response (open|filtered): protocol={} port={}",
                        res.host.orange(),
                        res.port.to_string().orange(),
                        proto.orange(),
                        res.port.to_string().orange()
                    )
                }
            } else if show_asn {
                format!(
                    "{}:{} timed out ({}): protocol={} port={}",
                    res.host.red(),
                    res.port.to_string().red(),
                    asn.red(),
                    proto.red(),
                    res.port.to_string().red()
                )
            } else {
                format!(
                    "{}:{} timed out: protocol={} port={}",
                    res.host.red(),
                    res.port.to_string().red(),
                    proto.red(),
                    res.port.to_string().red()
                )
            }
        }
    };
    format!("{prefix}{body}")
}

#[derive(Clone)]
struct ProbeUnit {
    host: String,
    ip: IpAddr,
    port: u16,
}

fn probe_units_concurrent(
    units: &[ProbeUnit],
    udp: bool,
    timeout_ms: u64,
    payloads: &HashMap<u16, Cow<'static, [u8]>>,
) -> Vec<PortVerdict> {
    let timeout_dur = Duration::from_millis(timeout_ms);
    let mut handles = Vec::with_capacity(units.len());
    for unit in units {
        let (ip, port) = (unit.ip, unit.port);
        let payload = payloads.get(&port).cloned().unwrap_or_default();
        handles.push((
            unit,
            thread::spawn(move || {
                if udp {
                    verdict_from_udp(udp_probe_once(
                        SocketAddr::new(ip, port),
                        &payload,
                        timeout_dur,
                    ))
                } else {
                    verdict_from_tcp(tcp_connect_once(ip, port, timeout_ms))
                }
            }),
        ));
    }

    handles
        .into_iter()
        .map(|(_, h)| h.join().unwrap_or(PortVerdict::NoResponse))
        .collect()
}

fn payloads_for(ports: &[u16], udp: bool) -> HashMap<u16, Cow<'static, [u8]>> {
    let mut map = HashMap::new();
    if udp {
        for &p in ports {
            map.insert(p, probe_payload(p));
        }
    }
    map
}

fn resolve_hosts_concurrent(hosts: &[String], port: u16) -> Vec<(String, Option<IpAddr>)> {
    let mut resolved = Vec::with_capacity(hosts.len());
    for chunk in hosts.chunks(RESOLVE_CHUNK) {
        let handles: Vec<_> = chunk
            .iter()
            .map(|host| {
                let host = host.clone();
                thread::spawn(move || {
                    let ip = resolve_ip(&host, port).ok().map(|a| a.ip());
                    (host, ip)
                })
            })
            .collect();
        for handle in handles {
            if let Ok(entry) = handle.join() {
                resolved.push(entry);
            }
        }
    }
    resolved
}

fn unique_ips<'a, I>(entries: I) -> Vec<IpAddr>
where
    I: Iterator<Item = &'a Option<IpAddr>>,
{
    let mut seen = HashSet::new();
    entries
        .flatten()
        .copied()
        .filter(|ip| seen.insert(*ip))
        .collect()
}

fn fetch_asns_concurrent(ips: &[IpAddr], no_asn: bool, timeout_ms: u64) -> HashMap<IpAddr, String> {
    let mut map = HashMap::with_capacity(ips.len());
    for chunk in ips.chunks(ASN_CHUNK) {
        let handles: Vec<_> = chunk
            .iter()
            .map(|&ip| {
                thread::spawn(move || {
                    let asn = fetch_asn(&ip.to_string(), no_asn, timeout_ms)
                        .unwrap_or_else(|_| "?".to_string());
                    (ip, asn)
                })
            })
            .collect();
        for handle in handles {
            if let Ok((ip, asn)) = handle.join() {
                map.insert(ip, asn);
            }
        }
    }
    map
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
    let timeout_dur = Duration::from_millis(timeout_ms);
    let resolved = resolve_hosts_concurrent(hosts, port);
    let asn_by_ip = fetch_asns_concurrent(
        &unique_ips(resolved.iter().map(|(_, ip)| ip)),
        no_asn,
        timeout_ms,
    );

    let proto_label = if udp { "UDP multi" } else { "TCP multi" };
    let payload = probe_payload(port);

    let mut stats = PingStats::default();
    let mut responsive_hosts: HashSet<String> = HashSet::new();

    for attempt_idx in 0..attempts {
        if !minimal && attempts > 1 {
            let message = format!("Attempt {}/{}", attempt_idx + 1, attempts);
            print_with_prefix(minimal, &message);
        }
        for chunk in resolved.chunks(CHUNK) {
            let mut handles = Vec::with_capacity(chunk.len());
            for (_, ip) in chunk {
                let Some(ip) = *ip else {
                    handles.push(None);
                    continue;
                };
                let payload = payload.clone();
                handles.push(Some(thread::spawn(move || {
                    if udp {
                        verdict_from_udp(udp_probe_once(
                            SocketAddr::new(ip, port),
                            &payload,
                            timeout_dur,
                        ))
                    } else {
                        verdict_from_tcp(tcp_connect_once(ip, port, timeout_ms))
                    }
                })));
            }
            for ((host, ip), handle) in chunk.iter().zip(handles) {
                let verdict = handle
                    .and_then(|h| h.join().ok())
                    .unwrap_or(PortVerdict::NoResponse);
                let asn = ip.map_or("resolve error", |ip| {
                    asn_by_ip.get(&ip).map_or("?", String::as_str)
                });
                let res = PortResult {
                    host: host.clone(),
                    port,
                    verdict,
                };
                let entry = format_port_result(&res, asn, udp, minimal);
                println!("{entry}");
                let rtt = match verdict {
                    PortVerdict::Open { rtt_us } => Some(rtt_us),
                    PortVerdict::Closed | PortVerdict::NoResponse => None,
                };
                stats.record(rtt.is_some(), rtt);
                if rtt.is_some() {
                    responsive_hosts.insert((*host).clone());
                }
            }
        }
        if attempt_idx + 1 != attempts {
            thread::sleep(Duration::from_secs(1));
        }
    }

    if minimal {
        let mut responsive_list: Vec<String> = responsive_hosts.iter().cloned().collect();
        responsive_list.sort();
        if !responsive_list.is_empty() {
            let entries = responsive_list
                .iter()
                .map(|h| h.green())
                .collect::<Vec<_>>()
                .join(", ");
            let message = format!("[{entries}]");
            print_with_prefix(minimal, &message);
        }
    }
    let summary = format!(
        "Hosts responsive: {}/{}",
        responsive_hosts.len().to_string().green(),
        hosts.len()
    );
    print_with_prefix(minimal, &summary);
    print_statistics(proto_label, &stats);
}

fn aggregate(results: &[PortResult], ports: &[u16], minimal: bool, proto_label: &str) {
    let mut stats = PingStats::default();
    let mut responsive_ports: HashSet<(String, u16)> = HashSet::new();

    for res in results {
        let rtt = match res.verdict {
            PortVerdict::Open { rtt_us } => Some(rtt_us),
            PortVerdict::Closed | PortVerdict::NoResponse => None,
        };
        stats.record(rtt.is_some(), rtt);
        if rtt.is_some() {
            responsive_ports.insert((res.host.clone(), res.port));
        }
    }

    if minimal {
        let mut list: Vec<(String, u16)> = responsive_ports.iter().cloned().collect();
        list.sort_by(|a, b| a.0.cmp(&b.0).then(a.1.cmp(&b.1)));
        if !list.is_empty() {
            let entries = list
                .iter()
                .map(|(h, p)| format!("{}:{}", h.green(), p.to_string().green()))
                .collect::<Vec<_>>()
                .join(", ");
            let message = format!("[{entries}]");
            print_with_prefix(minimal, &message);
        }
    }

    let unique_ports = ports.len();
    let summary = format!(
        "Ports responsive: {}/{} ({} unique ports)",
        responsive_ports.len().to_string().green(),
        stats.attempts(),
        unique_ports
    );
    print_with_prefix(minimal, &summary);
    print_statistics(proto_label, &stats);
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
    let payloads = payloads_for(ports, udp);

    let resolved_all = resolve_hosts_concurrent(hosts, ports[0]);
    let mut resolved: Vec<(String, IpAddr)> = Vec::with_capacity(hosts.len());
    for (host, ip) in &resolved_all {
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
        &unique_ips(resolved_all.iter().map(|(_, ip)| ip)),
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

    let mut all_results: Vec<PortResult> = Vec::with_capacity(resolved.len() * ports.len());

    for attempt_idx in 0..attempts {
        if !minimal && attempts > 1 {
            let message = format!("Attempt {}/{}", attempt_idx + 1, attempts);
            print_with_prefix(minimal, &message);
        }

        let mut units: Vec<ProbeUnit> = Vec::with_capacity(resolved.len() * ports.len());
        for (host, ip) in &resolved {
            for &port in ports {
                units.push(ProbeUnit {
                    host: host.clone(),
                    ip: *ip,
                    port,
                });
            }
        }

        for chunk in units.chunks(CHUNK) {
            let verdicts = probe_units_concurrent(chunk, udp, timeout_ms, &payloads);
            for (unit, verdict) in chunk.iter().zip(verdicts) {
                let asn = asn_by_ip.get(&unit.ip).map_or("?", String::as_str);
                let res = PortResult {
                    host: unit.host.clone(),
                    port: unit.port,
                    verdict,
                };
                let entry = format_port_result(&res, asn, udp, minimal);
                println!("{entry}");
                all_results.push(res);
            }
        }
    }

    aggregate(&all_results, ports, minimal, proto_label);
}

#[allow(clippy::too_many_arguments)]
pub fn perform_multiport_subnet<I>(
    host_label: &str,
    hosts: I,
    ports: &[u16],
    udp: bool,
    timeout_ms: u64,
    attempts: usize,
    minimal: bool,
    no_asn: bool,
) where
    I: Iterator<Item = IpAddr>,
{
    let attempts = attempts.max(1);
    let host_vec: Vec<IpAddr> = hosts.collect();
    if host_vec.is_empty() {
        let message = format!("{} has no usable host addresses", host_label.yellow());
        print_with_prefix(minimal, &message);
        return;
    }

    let subnet_asn =
        fetch_asn(&host_vec[0].to_string(), no_asn, timeout_ms).unwrap_or_else(|_| String::new());

    let proto_label = if udp { "UDP subnet" } else { "TCP subnet" };
    let header = if subnet_asn.is_empty() || subnet_asn == "no lookup" {
        format!(
            "Scanning {} ({} hosts) x {} ports via {}",
            host_label.bright_blue(),
            host_vec.len(),
            ports.len(),
            if udp { "UDP" } else { "TCP" }
        )
    } else {
        format!(
            "Scanning {} ({} hosts) x {} ports via {} [{}]",
            host_label.bright_blue(),
            host_vec.len(),
            ports.len(),
            if udp { "UDP" } else { "TCP" },
            subnet_asn.green()
        )
    };
    print_with_prefix(minimal, &header);

    let payloads = payloads_for(ports, udp);
    let mut all_results: Vec<PortResult> = Vec::with_capacity(host_vec.len() * ports.len());

    for attempt_idx in 0..attempts {
        if !minimal && attempts > 1 {
            let message = format!("Attempt {}/{}", attempt_idx + 1, attempts);
            print_with_prefix(minimal, &message);
        }

        let mut units: Vec<ProbeUnit> = Vec::with_capacity(host_vec.len() * ports.len());
        for &ip in &host_vec {
            for &port in ports {
                units.push(ProbeUnit {
                    host: ip.to_string(),
                    ip,
                    port,
                });
            }
        }

        for chunk in units.chunks(CHUNK) {
            let verdicts = probe_units_concurrent(chunk, udp, timeout_ms, &payloads);
            for (unit, verdict) in chunk.iter().zip(verdicts) {
                let res = PortResult {
                    host: unit.host.clone(),
                    port: unit.port,
                    verdict,
                };
                let entry = format_port_result(&res, "", udp, minimal);
                if matches!(verdict, PortVerdict::Open { .. }) {
                    println!("{entry}");
                }
                all_results.push(res);
            }
        }
    }

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
