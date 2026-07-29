use super::scan::{ScanConfig, ScanResult, format_scan_header, probe_chunk};
use crate::colors::Colorize;
use crate::output::format_with_prefix;
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

fn watch_pass_lines(results: &[ScanResult], pass: u64, minimal: bool) -> Vec<String> {
    if minimal {
        return vec![watch_minimal_line(results)];
    }

    let up = results.iter().filter(|r| r.is_responsive()).count();
    let mut lines = Vec::with_capacity(results.len().div_ceil(WATCH_HOSTS_PER_ROW) + 1);
    lines.push(format!(
        "Pass {pass} - {}/{} up",
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

const WATCH_MIN_PASS_INTERVAL: Duration = Duration::from_millis(150);

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
    use std::io::Write as _;
    use std::time::Instant;

    install_watch_interrupt_handler();

    let header = format_scan_header(
        "Watching",
        cfg.kind.header_protocol(),
        &cfg.notation,
        cfg.host_count,
        cfg.kind.header_port(),
        Some("(refreshing continuously, Ctrl+C to stop)"),
    );
    let header_line = format_with_prefix(cfg.minimal, &header);

    // Alternate screen buffer + hidden cursor, like htop/watch: keeps every
    // redrawn pass out of the shell's scrollback entirely instead of just
    // visually overwriting rows that are still recorded in history.
    print!("\x1b[?1049h\x1b[?25l");

    let mut seq: u16 = 1;
    let mut pass: u64 = 0;

    while !WATCH_INTERRUPTED.load(Ordering::SeqCst) {
        let pass_start = Instant::now();
        pass += 1;
        let results = probe_chunk(hosts, &cfg.kind, &mut seq);
        let content_lines = watch_pass_lines(&results, pass, cfg.minimal);

        println!("\x1b[H{header_line}");
        for line in &content_lines {
            println!("{line}");
        }
        print!("\x1b[J");
        let _ = std::io::stdout().flush();

        if WATCH_INTERRUPTED.load(Ordering::SeqCst) {
            break;
        }

        if let Some(remaining) = WATCH_MIN_PASS_INTERVAL.checked_sub(pass_start.elapsed()) {
            thread::sleep(remaining);
        }
    }

    print!("\x1b[?25h\x1b[?1049l");
    let _ = std::io::stdout().flush();
}
