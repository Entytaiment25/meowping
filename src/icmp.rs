use crate::colors::Colorize;
use crate::output::{color_time, print_statistics, print_with_prefix};
use std::collections::VecDeque;
use std::error::Error;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, ToSocketAddrs};
use std::time::{Duration, Instant};

pub const DEFAULT_ICMP_PAYLOAD: [u8; 24] = [
    46, 46, 46, 109, 101, 111, 119, 46, 46, 46, 109, 101, 111, 119, 46, 46, 46, 109, 101, 111, 119,
    46, 46, 46,
];

pub const DEFAULT_TTL: u8 = 64;
pub const DEFAULT_IDENT: u16 = 0;

fn resolve_ip(host: &str) -> std::io::Result<IpAddr> {
    if let Ok(ip) = host.parse::<IpAddr>() {
        return Ok(ip);
    }
    let addrs = (host, 0).to_socket_addrs()?;
    for addr in addrs {
        return Ok(addr.ip());
    }
    Err(std::io::Error::new(
        std::io::ErrorKind::AddrNotAvailable,
        "No IP address found for host",
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

    fn set_ttl_v6(fd: RawFd, ttl: u8) -> io::Result<()> {
        let ttl_val: libc::c_int = ttl as libc::c_int;
        let ret = unsafe {
            libc::setsockopt(
                fd,
                libc::IPPROTO_IPV6,
                libc::IPV6_UNICAST_HOPS,
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

    pub fn ping_once_ipv6(
        ip: Ipv6Addr,
        seq: u16,
        timeout: Duration,
        ttl: u8,
        ident: u16,
        payload: &[u8; 24],
    ) -> io::Result<(usize, Duration)> {
        let is_linux = cfg!(target_os = "linux");
        let sock_ty = if is_linux {
            libc::SOCK_DGRAM
        } else {
            libc::SOCK_RAW
        };
        let fd_raw = unsafe { libc::socket(libc::AF_INET6, sock_ty, libc::IPPROTO_ICMPV6) };
        if fd_raw < 0 {
            return Err(io::Error::last_os_error());
        }
        let fd = FdGuard { fd: fd_raw };

        set_recv_timeout(fd.fd, timeout)?;
        let _ = set_ttl_v6(fd.fd, ttl);

        let identifier = ident;

        let mut packet = vec![0u8; 8 + payload.len()];
        packet[0] = 128;
        packet[1] = 0;
        packet[2] = 0;
        packet[3] = 0;
        packet[4] = (identifier >> 8) as u8;
        packet[5] = (identifier & 0xff) as u8;
        packet[6] = (seq >> 8) as u8;
        packet[7] = (seq & 0xff) as u8;
        packet[8..8 + payload.len()].copy_from_slice(payload);

        if !is_linux {
            let csum = icmp_checksum(&packet);
            packet[2] = (csum >> 8) as u8;
            packet[3] = (csum & 0xff) as u8;
        }

        let mut addr: libc::sockaddr_in6 = unsafe { mem::zeroed() };
        addr.sin6_family = libc::AF_INET6 as libc::sa_family_t;
        addr.sin6_port = 0;
        addr.sin6_addr = libc::in6_addr {
            s6_addr: ip.octets(),
        };

        let addr_ptr = &addr as *const libc::sockaddr_in6 as *const libc::sockaddr;
        let addr_len = mem::size_of::<libc::sockaddr_in6>() as libc::socklen_t;

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

        let mut buf = vec![0u8; 1500];
        let mut from: libc::sockaddr_in6 = unsafe { mem::zeroed() };
        let mut from_len = mem::size_of::<libc::sockaddr_in6>() as libc::socklen_t;

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

        if n < 8 {
            return Err(io::Error::new(io::ErrorKind::Other, "Short ICMPv6 reply"));
        }

        let icmp_type = view[0];
        let icmp_code = view[1];
        let r_id = u16::from_be_bytes([view[4], view[5]]);
        let r_seq = u16::from_be_bytes([view[6], view[7]]);

        if icmp_type != 129 || icmp_code != 0 || !is_linux && (r_id != identifier || r_seq != seq) {
            return Err(io::Error::new(
                io::ErrorKind::Other,
                "Unexpected ICMPv6 reply",
            ));
        }

        Ok((n, rtt))
    }

    pub fn ping_once_ipv4(
        ip: Ipv4Addr,
        seq: u16,
        timeout: Duration,
        ttl: u8,
        ident: u16,
        payload: &[u8; 24],
    ) -> io::Result<(usize, Duration)> {
        let is_linux = cfg!(target_os = "linux");
        let sock_ty = if is_linux {
            libc::SOCK_DGRAM
        } else {
            libc::SOCK_RAW
        };
        let fd_raw = unsafe { libc::socket(libc::AF_INET, sock_ty, libc::IPPROTO_ICMP) };
        if fd_raw < 0 {
            return Err(io::Error::last_os_error());
        }
        let fd = FdGuard { fd: fd_raw };

        set_recv_timeout(fd.fd, timeout)?;
        let _ = set_ttl(fd.fd, ttl);

        let identifier = ident;

        let mut packet = vec![0u8; 8 + payload.len()];
        packet[0] = 8;
        packet[1] = 0;
        packet[2] = 0;
        packet[3] = 0;
        packet[4] = (identifier >> 8) as u8;
        packet[5] = (identifier & 0xff) as u8;
        packet[6] = (seq >> 8) as u8;
        packet[7] = (seq & 0xff) as u8;
        packet[8..8 + payload.len()].copy_from_slice(payload);

        let csum = icmp_checksum(&packet);
        packet[2] = (csum >> 8) as u8;
        packet[3] = (csum & 0xff) as u8;

        let mut addr: libc::sockaddr_in = unsafe { mem::zeroed() };
        addr.sin_family = libc::AF_INET as libc::sa_family_t;
        addr.sin_port = 0;
        addr.sin_addr = libc::in_addr {
            s_addr: u32::from_be_bytes(ip.octets()).to_be(),
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

        if icmp_type != 0 || icmp_code != 0 || !is_linux && (r_id != identifier || r_seq != seq) {
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
                u32::from_be_bytes(ip.octets()).to_be(),
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

pub fn ping_host_once(
    ip: IpAddr,
    seq: u16,
    timeout: Duration,
    ttl: u8,
    ident: u16,
    payload: &[u8; 24],
) -> std::io::Result<(usize, Duration)> {
    match ip {
        IpAddr::V4(ipv4) => platform::ping_once_ipv4(ipv4, seq, timeout, ttl, ident, payload),
        IpAddr::V6(ipv6) => {
            #[cfg(unix)]
            {
                platform::ping_once_ipv6(ipv6, seq, timeout, ttl, ident, payload)
            }
            #[cfg(not(unix))]
            {
                Err(std::io::Error::new(
                    std::io::ErrorKind::Unsupported,
                    "IPv6 is not supported on this platform",
                ))
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
    let ip = resolve_ip(destination)?;
    let timeout = Duration::from_millis(timeout_ms);

    let mut times: VecDeque<u128> = VecDeque::new();
    let mut successes = 0usize;

    for seq in 1..=count {
        let start = Instant::now();
        let result = ping_host_once(ip, seq as u16, timeout, ttl, ident, payload);
        let elapsed_us = start.elapsed().as_micros();

        match result {
            Ok((bytes, rtt)) => {
                successes += 1;
                times.push_back(rtt.as_micros());
                let time_ms = rtt.as_secs_f64() * 1000.0;
                let time_str = color_time(time_ms);
                let msg = format!(
                    "Reply from {}: bytes={} icmp_seq={} time={} TTL={} Identifier={}",
                    ip.to_string().green(),
                    bytes,
                    seq,
                    time_str,
                    ttl,
                    ident
                );
                print_with_prefix(minimal, msg);
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

    print_statistics("ICMP", count, successes, &times);
    Ok(())
}
