use crate::colors::Colorize;
use std::collections::VecDeque;
use std::error::Error;
use std::net::{IpAddr, Ipv4Addr, ToSocketAddrs};
use std::time::{Duration, Instant};

fn resolve_ipv4(host: &str) -> std::io::Result<Ipv4Addr> {
    if let Ok(ip) = host.parse::<Ipv4Addr>() {
        return Ok(ip);
    }
    let addrs = (host, 0).to_socket_addrs()?;
    for addr in addrs {
        if let IpAddr::V4(v4) = addr.ip() {
            return Ok(v4);
        }
    }
    Err(std::io::Error::new(
        std::io::ErrorKind::AddrNotAvailable,
        "No IPv4 address found for host",
    ))
}

#[cfg(unix)]
mod platform {
    use super::*;
    use std::io;
    use std::mem;
    use std::os::fd::RawFd;

    fn icmp_checksum(data: &[u8]) -> u16 {
        let mut sum: u32 = 0;
        let mut chunks = data.chunks_exact(2);
        for ch in &mut chunks {
            sum += u16::from_be_bytes([ch[0], ch[1]]) as u32;
        }
        if let Some(&rem) = chunks.remainder().first() {
            sum += u16::from_be_bytes([rem, 0]) as u32;
        }
        while (sum >> 16) != 0 {
            sum = (sum & 0xffff) + (sum >> 16);
        }
        !(sum as u16)
    }

    fn set_recv_timeout(fd: RawFd, timeout: Duration) -> io::Result<()> {
        let tv = libc::timeval {
            tv_sec: timeout.as_secs() as libc::time_t,
            tv_usec: timeout.subsec_micros() as libc::suseconds_t,
        };
        let ret = unsafe {
            libc::setsockopt(
                fd,
                libc::SOL_SOCKET,
                libc::SO_RCVTIMEO,
                &tv as *const _ as *const libc::c_void,
                mem::size_of::<libc::timeval>() as libc::socklen_t,
            )
        };
        if ret == -1 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }

    fn set_ttl(fd: RawFd, ttl: u8) -> io::Result<()> {
        let ttl_val: libc::c_int = ttl as libc::c_int;
        let ret = unsafe {
            libc::setsockopt(
                fd,
                libc::IPPROTO_IP,
                libc::IP_TTL,
                &ttl_val as *const _ as *const libc::c_void,
                mem::size_of::<libc::c_int>() as libc::socklen_t,
            )
        };
        if ret == -1 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }

    struct FdGuard {
        fd: RawFd,
    }
    impl Drop for FdGuard {
        fn drop(&mut self) {
            unsafe {
                libc::close(self.fd);
            }
        }
    }

    pub fn ping_once_ipv4(
        ip: Ipv4Addr,
        seq: u16,
        timeout: Duration,
        ttl: u8,
        ident: u16,
        payload: &[u8; 24],
    ) -> io::Result<(usize, Duration)> {
        let fd_raw = unsafe { libc::socket(libc::AF_INET, libc::SOCK_RAW, libc::IPPROTO_ICMP) };
        if fd_raw < 0 {
            return Err(io::Error::last_os_error());
        }
        let fd = FdGuard { fd: fd_raw };

        set_recv_timeout(fd.fd, timeout)?;
        let _ = set_ttl(fd.fd, ttl);

        // Build ICMP Echo Request: type(8), code(0), checksum, identifier, sequence, payload
        let identifier = ident;

        let mut packet = vec![0u8; 8 + payload.len()];
        packet[0] = 8; // Echo request
        packet[1] = 0; // Code
        packet[2] = 0;
        packet[3] = 0; // checksum placeholder
        packet[4] = (identifier >> 8) as u8;
        packet[5] = (identifier & 0xff) as u8;
        packet[6] = (seq >> 8) as u8;
        packet[7] = (seq & 0xff) as u8;
        packet[8..8 + payload.len()].copy_from_slice(payload);

        let csum = icmp_checksum(&packet);
        packet[2] = (csum >> 8) as u8;
        packet[3] = (csum & 0xff) as u8;

        // Destination sockaddr_in
        let mut addr: libc::sockaddr_in = unsafe { mem::zeroed() };
        addr.sin_family = libc::AF_INET as libc::sa_family_t;
        addr.sin_port = 0;
        addr.sin_addr = libc::in_addr {
            s_addr: u32::from_be_bytes(ip.octets()),
        };

        let addr_ptr = &addr as *const libc::sockaddr_in as *const libc::sockaddr;
        let addr_len = mem::size_of::<libc::sockaddr_in>() as libc::socklen_t;

        let send_time = Instant::now();
        let sent = unsafe {
            libc::sendto(
                fd.fd,
                packet.as_ptr() as *const libc::c_void,
                packet.len(),
                0,
                addr_ptr,
                addr_len,
            )
        };
        if sent < 0 {
            return Err(io::Error::last_os_error());
        }

        // Receive reply
        let mut buf = vec![0u8; 1500];
        let mut from: libc::sockaddr_in = unsafe { mem::zeroed() };
        let mut from_len = mem::size_of::<libc::sockaddr_in>() as libc::socklen_t;

        let received = unsafe {
            libc::recvfrom(
                fd.fd,
                buf.as_mut_ptr() as *mut libc::c_void,
                buf.len(),
                0,
                &mut from as *mut _ as *mut libc::sockaddr,
                &mut from_len as *mut _,
            )
        };
        if received < 0 {
            return Err(io::Error::last_os_error());
        }
        let rtt = send_time.elapsed();

        let n = received as usize;
        let view = &buf[..n];

        // Linux: IP header + ICMP. macOS/BSD: ICMP only.
        let mut off = 0usize;
        if !view.is_empty() && (view[0] >> 4) == 4 {
            let ihl = ((view[0] & 0x0f) as usize) * 4;
            if n >= ihl + 8 {
                off = ihl;
            }
        }
        if n < off + 8 {
            return Err(io::Error::new(io::ErrorKind::Other, "Short ICMP reply"));
        }

        let icmp = &view[off..];
        let icmp_type = icmp[0];
        let icmp_code = icmp[1];
        let r_id = u16::from_be_bytes([icmp[4], icmp[5]]);
        let r_seq = u16::from_be_bytes([icmp[6], icmp[7]]);

        if icmp_type != 0 || icmp_code != 0 || r_id != identifier || r_seq != seq {
            return Err(io::Error::new(
                io::ErrorKind::Other,
                "Unexpected ICMP reply",
            ));
        }

        let bytes = n - off;
        Ok((bytes, rtt))
    }
}

#[cfg(windows)]
mod platform {
    use super::*;
    use std::io;
    use std::mem;
    use windows_sys::Win32::Foundation::INVALID_HANDLE_VALUE;
    use windows_sys::Win32::NetworkManagement::IpHelper::{
        ICMP_ECHO_REPLY, IcmpCloseHandle, IcmpCreateFile, IcmpSendEcho,
    };

    struct HandleGuard(isize);
    impl Drop for HandleGuard {
        fn drop(&mut self) {
            unsafe {
                IcmpCloseHandle(self.0 as *mut std::ffi::c_void);
            }
        }
    }

    pub fn ping_once_ipv4(
        ip: Ipv4Addr,
        _seq: u16,
        timeout: Duration,
        _ttl: u8,
        _ident: u16,
        payload: &[u8; 24],
    ) -> io::Result<(usize, Duration)> {
        unsafe {
            let handle = IcmpCreateFile();
            if handle == INVALID_HANDLE_VALUE {
                return Err(io::Error::last_os_error());
            }
            let handle = HandleGuard(handle as isize);

            let mut reply_buf = vec![0u8; mem::size_of::<ICMP_ECHO_REPLY>() + payload.len() + 8];

            let start = Instant::now();
            let num = IcmpSendEcho(
                handle.0 as *mut std::ffi::c_void,
                u32::from_be_bytes(ip.octets()),
                payload.as_ptr() as _,
                payload.len() as u16,
                std::ptr::null(),
                reply_buf.as_mut_ptr() as _,
                reply_buf.len() as u32,
                timeout.as_millis() as u32,
            );
            let rtt = start.elapsed();

            if num > 0 {
                let rep = &*(reply_buf.as_ptr() as *const ICMP_ECHO_REPLY);
                Ok((rep.DataSize as usize, rtt))
            } else {
                Err(io::Error::last_os_error())
            }
        }
    }
}

pub fn perform_icmp(
    destination: &str,
    timeout_ms: u64,
    ttl: u8,
    ident: u16,
    count: usize,
    payload: &[u8; 24],
    minimal: bool,
) -> Result<(), Box<dyn Error>> {
    let ip = resolve_ipv4(destination)?;
    let timeout = Duration::from_millis(timeout_ms);

    let mut times: VecDeque<u128> = VecDeque::new();
    let mut successes = 0usize;

    for seq in 1..=count {
        let start = Instant::now();
        let result = platform::ping_once_ipv4(ip, seq as u16, timeout, ttl, ident, payload);
        let elapsed_us = start.elapsed().as_micros();

        match result {
            Ok((bytes, rtt)) => {
                successes += 1;
                times.push_back(rtt.as_micros());
                let msg = format!(
                    "Reply from {}: bytes={} icmp_seq={} time={:.2}ms TTL={} Identifier={}",
                    ip,
                    bytes,
                    seq,
                    rtt.as_secs_f64() * 1000.0,
                    ttl,
                    ident
                );
                print_with_prefix(minimal, msg.green());
            }
            Err(_e) => {
                times.push_back(0);
                let msg = format!(
                    "Request timeout for icmp_seq {} time={:.2}ms TTL={} Identifier={}",
                    seq,
                    (elapsed_us as f64) / 1000.0,
                    ttl,
                    ident
                );
                print_with_prefix(minimal, msg.red());
            }
        }

        if seq != count {
            std::thread::sleep(Duration::from_secs(1));
        }
    }

    print_statistics(count, successes, &times);
    Ok(())
}

fn print_with_prefix(minimal: bool, message: String) {
    if minimal {
        println!("{}", message);
    } else {
        println!("{} {}", "[MEOWPING]".magenta(), message);
    }
}

fn print_statistics(count: usize, successes: usize, times: &VecDeque<u128>) {
    let failed = count - successes;

    let good_times: Vec<u128> = times.iter().copied().filter(|&t| t > 0).collect();

    let min_time = if !good_times.is_empty() {
        (*good_times.iter().min().unwrap() as f32) / 1000.0
    } else {
        0.0
    };

    let max_time = if !good_times.is_empty() {
        (*good_times.iter().max().unwrap() as f32) / 1000.0
    } else {
        0.0
    };

    let avg_time = if !good_times.is_empty() {
        (good_times.iter().sum::<u128>() as f32) / (good_times.len() as f32) / 1000.0
    } else {
        0.0
    };

    println!("\nPing statistics:");
    println!(
        "\tAttempted = {}, Successes = {}, Failures = {} ({} loss)",
        count.to_string().blue(),
        successes.to_string().blue(),
        failed.to_string().blue(),
        format!(
            "{:.2}%",
            ((failed as f32) / (count as f32).max(1.0)) * 100.0
        )
        .blue()
    );
    println!("Approximate round trip times:");
    println!(
        "\tMinimum = {}, Maximum = {}, Average = {}",
        format!("{:.2}ms", min_time).blue(),
        format!("{:.2}ms", max_time).blue(),
        format!("{:.2}ms", avg_time).blue()
    );
}
