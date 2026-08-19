use super::scan::{
    ScanConfig, ScanResult, ensure_rounds, format_scan_header, print_host_summary,
    print_responsive_minimal, probe_chunk,
};
use crate::colors::Colorize;
use crate::output::{PingStats, format_with_prefix, print_statistics};
use std::collections::HashSet;
use std::net::IpAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread;
use std::time::Duration;

const WATCH_HOSTS_PER_ROW: usize = 8;

fn watch_minimal_line(results: &[ScanResult]) -> String {
    let mut responsive: Vec<IpAddr> = results
        .iter()
        .filter(|r| r.is_responsive())
        .map(|r| r.host)
        .collect();
    responsive.sort_by_key(|ip| match ip {
        IpAddr::V4(v4) => (0, u128::from(u32::from(*v4))),
        IpAddr::V6(v6) => (1, u128::from(*v6)),
    });
    let entries = responsive
        .iter()
        .map(|ip| ip.to_string().green())
        .collect::<Vec<_>>()
        .join(", ");
    format!("[{entries}]")
}

fn watch_round_lines(results: &[ScanResult], round: u64, minimal: bool) -> Vec<String> {
    if minimal {
        return vec![watch_minimal_line(results)];
    }

    let up = results.iter().filter(|r| r.is_responsive()).count();
    let mut lines = Vec::with_capacity(results.len().div_ceil(WATCH_HOSTS_PER_ROW) + 1);
    lines.push(format!(
        "Round {round} - {}/{} up",
        up.to_string().green(),
        results.len()
    ));
    for chunk in results.chunks(WATCH_HOSTS_PER_ROW) {
        let entries = chunk
            .iter()
            .map(|status| status.format(false))
            .collect::<Vec<_>>()
            .join(", ");
        lines.push(format!("[{entries}]"));
    }
    lines
}

const WATCH_MIN_ROUND_INTERVAL: Duration = Duration::from_millis(150);

static WATCH_INTERRUPTED: AtomicBool = AtomicBool::new(false);

#[cfg(unix)]
extern "C" fn watch_signal_handler(_sig: libc::c_int) {
    WATCH_INTERRUPTED.store(true, Ordering::SeqCst);
}

#[cfg(unix)]
fn install_watch_interrupt_handler() {
    unsafe {
        libc::signal(
            libc::SIGINT,
            watch_signal_handler as *const () as libc::sighandler_t,
        );
    }
}

#[cfg(windows)]
unsafe extern "system" fn watch_ctrl_handler(ctrl_type: u32) -> i32 {
    use windows_sys::Win32::System::Console::{CTRL_BREAK_EVENT, CTRL_C_EVENT};
    if ctrl_type == CTRL_C_EVENT || ctrl_type == CTRL_BREAK_EVENT {
        WATCH_INTERRUPTED.store(true, Ordering::SeqCst);
        1
    } else {
        0
    }
}

#[cfg(windows)]
fn install_watch_interrupt_handler() {
    use windows_sys::Win32::System::Console::SetConsoleCtrlHandler;
    unsafe {
        SetConsoleCtrlHandler(Some(watch_ctrl_handler), 1);
    }
}

pub(super) fn perform_subnet_watch(hosts: &[IpAddr], cfg: &ScanConfig) {
    use std::io::{IsTerminal as _, Write as _};
    use std::time::Instant;

    install_watch_interrupt_handler();

    let max_rounds = cfg.rounds.map(ensure_rounds);
    let suffix = max_rounds.map_or_else(
        || "(refreshing continuously, Ctrl+C to stop)".to_string(),
        |n| format!("({n} rounds)"),
    );

    let header = format_scan_header(
        "Watching",
        cfg.kind.header_protocol(),
        &cfg.notation,
        cfg.host_count,
        cfg.kind.header_port(),
        Some(&suffix),
    );
    let header_line = format_with_prefix(cfg.minimal, &header);
    let live_redraw = std::io::stdout().is_terminal();

    if live_redraw {
        print!("\x1b[?1049h\x1b[?25l");
    } else {
        println!("{header_line}");
    }

    let mut seq: u16 = 1;
    let mut round: u64 = 0;
    let mut stats = PingStats::default();
    let mut responsive_hosts: HashSet<IpAddr> = HashSet::new();

    while !WATCH_INTERRUPTED.load(Ordering::SeqCst) {
        if max_rounds.is_some_and(|limit| round >= u64::try_from(limit).unwrap_or(u64::MAX)) {
            break;
        }

        let round_start = Instant::now();
        round += 1;
        let results = probe_chunk(hosts, &cfg.kind, &mut seq);

        for status in &results {
            stats.record(status.is_responsive(), status.latency_us());
            if status.is_responsive() {
                responsive_hosts.insert(status.host);
            }
        }

        let content_lines = watch_round_lines(&results, round, cfg.minimal);

        if live_redraw {
            println!("\x1b[H{header_line}");
            for line in &content_lines {
                println!("{line}");
            }
            print!("\x1b[J");
            let _ = std::io::stdout().flush();
        } else {
            for line in &content_lines {
                println!("{line}");
            }
        }

        if WATCH_INTERRUPTED.load(Ordering::SeqCst) {
            break;
        }

        if let Some(remaining) = WATCH_MIN_ROUND_INTERVAL.checked_sub(round_start.elapsed()) {
            thread::sleep(remaining);
        }
    }

    if live_redraw {
        print!("\x1b[?25h\x1b[?1049l");
        let _ = std::io::stdout().flush();
    }

    if cfg.minimal {
        print_responsive_minimal(&responsive_hosts, cfg.minimal);
    }
    print_host_summary(hosts.len(), responsive_hosts.len(), cfg.minimal);
    print_statistics(&format!("{} subnet", cfg.kind.header_protocol()), &stats);
}
