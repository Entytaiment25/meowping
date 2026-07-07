use crate::colors::Colorize;
use crate::output::{color_time, micros_to_ms, print_statistics, print_with_prefix};
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
    let mut addrs = (host, 0).to_socket_addrs()?;
    if let Some(addr) = addrs.next() {
        return Ok(addr.ip());
    }
    Err(std::io::Error::new(
        std::io::ErrorKind::AddrNotAvailable,
        "No IP address found for host",
    ))
}

#[cfg(unix)]
mod platform {
    use super::{Duration, Instant, Ipv4Addr, Ipv6Addr};
    use std::io;
    use std::mem;
    use std::os::fd::RawFd;

    fn socklen_of<T>() -> io::Result<libc::socklen_t> {
        libc::socklen_t::try_from(mem::size_of::<T>())
            .map_err(|_| io::Error::other("socklen_t overflow"))
    }

    fn sa_family(value: libc::c_int) -> io::Result<libc::sa_family_t> {
        libc::sa_family_t::try_from(value).map_err(|_| io::Error::other("sa_family_t overflow"))
    }

    fn icmp_checksum(data: &[u8]) -> u16 {
        let mut sum: u32 = 0;
        let (chunks, remainder) = data.as_chunks::<2>();
        for ch in chunks {
            sum += u32::from(u16::from_be_bytes([ch[0], ch[1]]));
        }
        if let Some(&rem) = remainder.first() {
            sum += u32::from(u16::from_be_bytes([rem, 0]));
        }
        while (sum >> 16) != 0 {
            sum = (sum & 0xffff) + (sum >> 16);
        }
        !u16::try_from(sum).expect("ICMP checksum fold must fit into u16")
    }

    fn setsockopt_raw(
        fd: RawFd,
        level: libc::c_int,
        name: libc::c_int,
        val: *const libc::c_void,
        len: libc::socklen_t,
    ) -> io::Result<()> {
        let ret = unsafe { libc::setsockopt(fd, level, name, val, len) };
        if ret == -1 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }

    fn set_recv_timeout(fd: RawFd, timeout: Duration) -> io::Result<()> {
        let tv = libc::timeval {
            tv_sec: libc::time_t::try_from(timeout.as_secs())
                .map_err(|_| io::Error::other("timeout seconds overflow time_t"))?,
            tv_usec: libc::suseconds_t::try_from(timeout.subsec_micros())
                .map_err(|_| io::Error::other("timeout micros overflow suseconds_t"))?,
        };
        setsockopt_raw(
            fd,
            libc::SOL_SOCKET,
            libc::SO_RCVTIMEO,
            (&raw const tv).cast::<libc::c_void>(),
            socklen_of::<libc::timeval>()?,
        )
    }

    fn setsockopt_int(
        fd: RawFd,
        level: libc::c_int,
        name: libc::c_int,
        val: libc::c_int,
    ) -> io::Result<()> {
        setsockopt_raw(
            fd,
            level,
            name,
            (&raw const val).cast::<libc::c_void>(),
            socklen_of::<libc::c_int>()?,
        )
    }

    fn set_ttl(fd: RawFd, ttl: u8) -> io::Result<()> {
        setsockopt_int(fd, libc::IPPROTO_IP, libc::IP_TTL, libc::c_int::from(ttl))
    }

    fn set_ttl_v6(fd: RawFd, ttl: u8) -> io::Result<()> {
        setsockopt_int(
            fd,
            libc::IPPROTO_IPV6,
            libc::IPV6_UNICAST_HOPS,
            libc::c_int::from(ttl),
        )
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
        let fd_raw =
            unsafe { libc::socket(libc::AF_INET6, libc::SOCK_DGRAM, libc::IPPROTO_ICMPV6) };
        let is_dgram = fd_raw >= 0;
        let fd_raw = if fd_raw < 0 {
            unsafe { libc::socket(libc::AF_INET6, libc::SOCK_RAW, libc::IPPROTO_ICMPV6) }
        } else {
            fd_raw
        };
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

        let mut addr: libc::sockaddr_in6 = unsafe { mem::zeroed() };
        addr.sin6_family = sa_family(libc::AF_INET6)?;
        addr.sin6_port = 0;
        addr.sin6_addr = libc::in6_addr {
            s6_addr: ip.octets(),
        };

        let addr_ptr = (&raw const addr).cast::<libc::sockaddr>();
        let addr_len = socklen_of::<libc::sockaddr_in6>()?;

        let send_time = Instant::now();
        let sent = unsafe {
            libc::sendto(
                fd.fd,
                packet.as_ptr().cast::<libc::c_void>(),
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
        let mut from_len = socklen_of::<libc::sockaddr_in6>()?;

        let received = unsafe {
            libc::recvfrom(
                fd.fd,
                buf.as_mut_ptr().cast::<libc::c_void>(),
                buf.len(),
                0,
                (&raw mut from).cast::<libc::sockaddr>(),
                &raw mut from_len,
            )
        };
        if received < 0 {
            return Err(io::Error::last_os_error());
        }
        let rtt = send_time.elapsed();

        let n = received.cast_unsigned();
        let view = &buf[..n];

        if n < 8 {
            return Err(io::Error::other("Short ICMPv6 reply"));
        }

        let icmp_type = view[0];
        let icmp_code = view[1];
        let r_id = u16::from_be_bytes([view[4], view[5]]);
        let r_seq = u16::from_be_bytes([view[6], view[7]]);

        if icmp_type != 129 || icmp_code != 0 || (!is_dgram && (r_id != identifier || r_seq != seq))
        {
            return Err(io::Error::other("Unexpected ICMPv6 reply"));
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
        addr.sin_family = sa_family(libc::AF_INET)?;
        addr.sin_port = 0;
        addr.sin_addr = libc::in_addr {
            s_addr: u32::from_be_bytes(ip.octets()).to_be(),
        };

        let addr_ptr = (&raw const addr).cast::<libc::sockaddr>();
        let addr_len = socklen_of::<libc::sockaddr_in>()?;

        let send_time = Instant::now();
        let sent = unsafe {
            libc::sendto(
                fd.fd,
                packet.as_ptr().cast::<libc::c_void>(),
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
        let mut from_len = socklen_of::<libc::sockaddr_in>()?;

        let received = unsafe {
            libc::recvfrom(
                fd.fd,
                buf.as_mut_ptr().cast::<libc::c_void>(),
                buf.len(),
                0,
                (&raw mut from).cast::<libc::sockaddr>(),
                &raw mut from_len,
            )
        };
        if received < 0 {
            return Err(io::Error::last_os_error());
        }
        let rtt = send_time.elapsed();

        let n = received.cast_unsigned();
        let view = &buf[..n];

        let mut off = 0usize;
        if !view.is_empty() && (view[0] >> 4) == 4 {
            let ihl = usize::from(view[0] & 0x0f) * 4;
            if n >= ihl + 8 {
                off = ihl;
            }
        }
        if n < off + 8 {
            return Err(io::Error::other("Short ICMP reply"));
        }

        let icmp = &view[off..];
        let icmp_type = icmp[0];
        let icmp_code = icmp[1];
        let r_id = u16::from_be_bytes([icmp[4], icmp[5]]);
        let r_seq = u16::from_be_bytes([icmp[6], icmp[7]]);

        if icmp_type != 0 || icmp_code != 0 || !is_linux && (r_id != identifier || r_seq != seq) {
            return Err(io::Error::other("Unexpected ICMP reply"));
        }

        let bytes = n - off;
        Ok((bytes, rtt))
    }
}

#[cfg(windows)]
mod platform {
    use super::{Duration, Instant, Ipv4Addr, Ipv6Addr};
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
                payload.as_ptr().cast(),
                u16::try_from(payload.len()).unwrap_or(u16::MAX),
                std::ptr::null(),
                reply_buf.as_mut_ptr().cast(),
                u32::try_from(reply_buf.len()).unwrap_or(u32::MAX),
                u32::try_from(timeout.as_millis()).unwrap_or(u32::MAX),
            );
            let rtt = start.elapsed();

            if num > 0 {
                let rep = std::ptr::read_unaligned(reply_buf.as_ptr().cast::<ICMP_ECHO_REPLY>());
                Ok((usize::from(rep.DataSize), rtt))
            } else {
                Err(io::Error::last_os_error())
            }
        }
    }

    pub fn ping_once_ipv6(
        ip: Ipv6Addr,
        _seq: u16,
        timeout: Duration,
        _ttl: u8,
        _ident: u16,
        payload: &[u8; 24],
    ) -> io::Result<(usize, Duration)> {
        #[repr(C)]
        #[allow(clippy::struct_field_names)]
        struct SockAddrIn6 {
            sin6_family: u16,
            sin6_port: u16,
            sin6_flowinfo: u32,
            sin6_addr: [u8; 16],
            sin6_scope_id: u32,
        }

        #[link(name = "iphlpapi")]
        unsafe extern "system" {
            fn Icmp6CreateFile() -> isize;
            fn Icmp6SendEcho2(
                icmphandle: isize,
                event: isize,
                apcroutine: usize,
                apccontext: usize,
                sourceaddress: *const SockAddrIn6,
                destinationaddress: *const SockAddrIn6,
                requestdata: *const u8,
                requestsize: u16,
                requestoptions: usize,
                replybuffer: *mut u8,
                replysize: u32,
                timeout: u32,
            ) -> u32;
        }

        unsafe {
            let handle = Icmp6CreateFile();
            if handle == INVALID_HANDLE_VALUE as isize {
                return Err(io::Error::last_os_error());
            }
            let handle = HandleGuard(handle);

            let src_addr = SockAddrIn6 {
                sin6_family: 23, // AF_INET6
                sin6_port: 0,
                sin6_flowinfo: 0,
                sin6_addr: [0u8; 16],
                sin6_scope_id: 0,
            };

            let dst_addr = SockAddrIn6 {
                sin6_family: 23,
                sin6_port: 0,
                sin6_flowinfo: 0,
                sin6_addr: ip.octets(),
                sin6_scope_id: 0,
            };

            // ICMPV6_ECHO_REPLY_LH (36 bytes) + payload + 8 bytes for ICMP error message + IO_STATUS_BLOCK (16 bytes on 64-bit)
            let reply_size = 36 + payload.len() + 8 + 32;
            let mut reply_buf = vec![0u8; reply_size];

            let start = Instant::now();
            let num = Icmp6SendEcho2(
                handle.0,
                0, // event = NULL
                0, // apcroutine = NULL
                0, // apccontext = NULL
                &raw const src_addr,
                &raw const dst_addr,
                payload.as_ptr(),
                u16::try_from(payload.len()).unwrap_or(u16::MAX),
                0, // requestoptions = NULL
                reply_buf.as_mut_ptr(),
                u32::try_from(reply_size).unwrap_or(u32::MAX),
                u32::try_from(timeout.as_millis()).unwrap_or(u32::MAX),
            );
            let rtt = start.elapsed();

            if num > 0 {
                Ok((payload.len(), rtt))
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
        IpAddr::V6(ipv6) => platform::ping_once_ipv6(ipv6, seq, timeout, ttl, ident, payload),
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
    let mut seq: u16 = 1;

    for attempt_idx in 0..count {
        let start = Instant::now();
        let result = ping_host_once(ip, seq, timeout, ttl, ident, payload);
        let elapsed_us = start.elapsed().as_micros();
        let display_seq = attempt_idx + 1;

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
                    display_seq,
                    time_str,
                    ttl,
                    ident
                );
                print_with_prefix(minimal, &msg);
            }
            Err(_e) => {
                times.push_back(0);
                let msg = format!(
                    "Request timeout for icmp_seq {} time={:.2}ms TTL={} Identifier={}",
                    display_seq,
                    micros_to_ms(elapsed_us),
                    ttl,
                    ident
                );
                let message = msg.red();
                print_with_prefix(minimal, &message);
            }
        }

        if display_seq != count {
            std::thread::sleep(Duration::from_secs(1));
        }
        seq = seq.wrapping_add(1);
    }

    print_statistics("ICMP", count, successes, &times);
    Ok(())
}
