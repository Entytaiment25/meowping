use crate::colors::Colorize;
use crate::output::{color_time, micros_to_ms, print_statistics, print_with_prefix};
use crate::tcp::{fetch_asn, resolve_ip, tcp_connect_once};
use crate::udp::{ProbeOutcome, probe_payload, udp_probe_once};
use std::collections::{HashMap, HashSet, VecDeque};
use std::net::IpAddr;
use std::thread;
use std::time::Duration;

const CHUNK: usize = 32;

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

#[derive(Clone, Copy, PartialEq, Eq)]
struct ProbeUnit {
    ip: IpAddr,
    port: u16,
}

fn probe_units_concurrent(
    units: &[ProbeUnit],
    udp: bool,
    timeout_ms: u64,
    payloads: &HashMap<u16, Vec<u8>>,
) -> Vec<PortVerdict> {
    let timeout_dur = Duration::from_millis(timeout_ms);
    let mut handles = Vec::with_capacity(units.len());
    for &unit in units {
        let payload = if udp {
            payloads.get(&unit.port).cloned()
        } else {
            None
        };
        handles.push((
            unit,
            thread::spawn(move || {
                if udp {
                    let payload = payload.unwrap_or_default();
                    verdict_from_udp(udp_probe_once(
                        std::net::SocketAddr::new(unit.ip, unit.port),
                        &payload,
                        timeout_dur,
                    ))
                } else {
                    verdict_from_tcp(tcp_connect_once(unit.ip, unit.port, timeout_ms))
                }
            }),
        ));
    }

    handles
        .into_iter()
        .map(|(_, h)| h.join().unwrap_or(PortVerdict::NoResponse))
        .collect()
}

fn payloads_for(ports: &[u16], udp: bool) -> HashMap<u16, Vec<u8>> {
    let mut map = HashMap::new();
    if udp {
        for &p in ports {
            map.insert(p, probe_payload(p));
        }
    }
    map
}

fn aggregate(results: &[PortResult], ports: &[u16], udp: bool, minimal: bool, proto_label: &str) {
    let mut times: VecDeque<u128> = VecDeque::new();
    let mut successes = 0usize;
    let mut responsive_ports: HashSet<(String, u16)> = HashSet::new();

    for res in results {
        match res.verdict {
            PortVerdict::Open { rtt_us } => {
                successes += 1;
                responsive_ports.insert((res.host.clone(), res.port));
                times.push_back(rtt_us);
            }
            _ => times.push_back(0),
        }
    }

    let total = results.len();
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
        total,
        unique_ports
    );
    print_with_prefix(minimal, &summary);
    let _ = udp;
    print_statistics(proto_label, total, successes, &times);
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

    let mut resolved: Vec<(String, IpAddr)> = Vec::with_capacity(hosts.len());
    for host in hosts {
        if let Ok(addr) = resolve_ip(host, ports[0]) {
            if !minimal && addr.ip().to_string() != *host {
                crate::tcp::print_ip_info(host, &addr.ip().to_string(), minimal);
            }
            resolved.push((host.clone(), addr.ip()));
        } else {
            let message = format!("DNS Lookup of domain failed: Invalid host or URL: {host}");
            print_with_prefix(minimal, &message);
        }
    }
    if resolved.is_empty() {
        return;
    }

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
        for (_, ip) in &resolved {
            for &port in ports {
                units.push(ProbeUnit { ip: *ip, port });
            }
        }

        for chunk in units.chunks(CHUNK) {
            let verdicts = probe_units_concurrent(chunk, udp, timeout_ms, &payloads);
            for (unit, verdict) in chunk.iter().zip(verdicts) {
                let host = resolved
                    .iter()
                    .find(|(_, ip)| ip == &unit.ip)
                    .map_or_else(|| unit.ip.to_string(), |(h, _)| h.clone());
                let asn = fetch_asn(&unit.ip.to_string(), no_asn, timeout_ms)
                    .unwrap_or_else(|_| "?".to_string());
                let res = PortResult {
                    host: host.clone(),
                    port: unit.port,
                    verdict,
                };
                let entry = format_port_result(&res, &asn, udp, minimal);
                println!("{entry}");
                all_results.push(res);
            }
        }
    }

    aggregate(&all_results, ports, udp, minimal, proto_label);
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
                units.push(ProbeUnit { ip, port });
            }
        }

        for chunk in units.chunks(CHUNK) {
            let verdicts = probe_units_concurrent(chunk, udp, timeout_ms, &payloads);
            for (unit, verdict) in chunk.iter().zip(verdicts) {
                let res = PortResult {
                    host: unit.ip.to_string(),
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

    aggregate(&all_results, ports, udp, minimal, proto_label);
}
