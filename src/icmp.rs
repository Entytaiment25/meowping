use crate::colors::Colorize;
use crate::output::{
    PingStats, TIME_COLUMN_WIDTH, color_time_padded, format_ms, micros, print_statistics,
    print_with_prefix,
};
use std::error::Error;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::time::{Duration, Instant};

pub const MEOW_ICMP_PAYLOAD: [u8; 24] = [
    46, 46, 46, 109, 101, 111, 119, 46, 46, 46, 109, 101, 111, 119, 46, 46, 46, 109, 101, 111, 119,
    46, 46, 46,
];

pub const CLASSIC_ICMP_PAYLOAD: [u8; 24] = [
    8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31,
];

pub const DEFAULT_TTL: u8 = 64;
pub const DEFAULT_IDENT: u16 = 0;

#[cfg(unix)]
mod platform {
    use super::{Duration, Instant, Ipv4Addr, Ipv6Addr};
    use std::io;
    use std::net::{SocketAddr, UdpSocket};
    use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};

    fn retry_on_eintr<T>(mut f: impl FnMut() -> io::Result<T>) -> io::Result<T> {
        loop {
            match f() {
                Err(err) if err.kind() == io::ErrorKind::Interrupted => {}
                result => return result,
            }
        }
    }

    fn icmp_socket(domain: libc::c_int, protocol: libc::c_int) -> io::Result<(UdpSocket, bool)> {
        for (ty, is_dgram) in [(libc::SOCK_DGRAM, true), (libc::SOCK_RAW, false)] {
            // SAFETY: socket() takes plain integers and returns a new descriptor or -1. A new
            // descriptor is owned by nobody else, so `OwnedFd` can take it and close it once.
            let fd = unsafe {
                let fd = libc::socket(domain, ty, protocol);
                if fd < 0 {
                    None
                } else {
                    Some(OwnedFd::from_raw_fd(fd))
                }
            };
            if let Some(fd) = fd {
                return Ok((UdpSocket::from(fd), is_dgram));
            }
        }
        Err(io::Error::last_os_error())
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
        // The fold above leaves the sum within 16 bits.
        let [_, _, hi, lo] = sum.to_be_bytes();
        !u16::from_be_bytes([hi, lo])
    }

    fn set_ttl_v6(sock: &UdpSocket, ttl: u8) -> io::Result<()> {
        let val = libc::c_int::from(ttl);
        let len = libc::socklen_t::try_from(size_of::<libc::c_int>())
            .map_err(|_| io::Error::other("socklen_t overflow"))?;
        // SAFETY: `val` points to a live value of `len` bytes, owned by the caller for this call.
        let ret = unsafe {
            libc::setsockopt(
                sock.as_raw_fd(),
                libc::IPPROTO_IPV6,
                libc::IPV6_UNICAST_HOPS,
                (&raw const val).cast::<libc::c_void>(),
                len,
            )
        };
        if ret == -1 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }

    fn send_and_receive(
        sock: &UdpSocket,
        packet: &[u8],
        dest: SocketAddr,
        buf: &mut [u8],
    ) -> io::Result<(usize, Duration)> {
        let send_time = Instant::now();
        retry_on_eintr(|| sock.send_to(packet, dest))?;
        let received = retry_on_eintr(|| sock.recv(buf))?;
        Ok((received, send_time.elapsed()))
    }

    pub fn ping_once_ipv6(
        ip: Ipv6Addr,
        seq: u16,
        timeout: Duration,
        ttl: u8,
        ident: u16,
        payload: &[u8; 24],
    ) -> io::Result<(usize, Duration)> {
        let (sock, is_dgram) = icmp_socket(libc::AF_INET6, libc::IPPROTO_ICMPV6)?;

        sock.set_read_timeout((!timeout.is_zero()).then_some(timeout))?;
        let _ = set_ttl_v6(&sock, ttl);

        let identifier = ident;

        let mut packet = [0u8; 32];
        packet[0] = 128;
        packet[1] = 0;
        packet[2] = 0;
        packet[3] = 0;
        packet[4] = (identifier >> 8) as u8;
        packet[5] = (identifier & 0xff) as u8;
        packet[6] = (seq >> 8) as u8;
        packet[7] = (seq & 0xff) as u8;
        packet[8..].copy_from_slice(payload);

        let mut buf = [0u8; 1500];
        let (n, rtt) = send_and_receive(&sock, &packet, SocketAddr::new(ip.into(), 0), &mut buf)?;
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
        let (sock, is_dgram) = icmp_socket(libc::AF_INET, libc::IPPROTO_ICMP)?;

        sock.set_read_timeout((!timeout.is_zero()).then_some(timeout))?;
        let _ = sock.set_ttl(u32::from(ttl));

        let identifier = ident;

        let mut packet = [0u8; 32];
        packet[0] = 8;
        packet[1] = 0;
        packet[2] = 0;
        packet[3] = 0;
        packet[4] = (identifier >> 8) as u8;
        packet[5] = (identifier & 0xff) as u8;
        packet[6] = (seq >> 8) as u8;
        packet[7] = (seq & 0xff) as u8;
        packet[8..].copy_from_slice(payload);

        let csum = icmp_checksum(&packet);
        packet[2] = (csum >> 8) as u8;
        packet[3] = (csum & 0xff) as u8;

        let mut buf = [0u8; 1500];
        let (n, rtt) = send_and_receive(&sock, &packet, SocketAddr::new(ip.into(), 0), &mut buf)?;
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
        if icmp_type != 0 || icmp_code != 0 || (!is_dgram && (r_id != identifier || r_seq != seq)) {
            return Err(io::Error::other("Unexpected ICMP reply"));
        }

        let bytes = n - off;
        Ok((bytes, rtt))
    }

    #[cfg(test)]
    mod checksum_tests {
        use super::icmp_checksum;

        #[test]
        fn rfc1071_worked_example() {
            let data = [0x00u8, 0x01, 0xf2, 0x03, 0xf4, 0xf5, 0xf6, 0xf7];
            assert_eq!(icmp_checksum(&data), 0x220d);
        }

        #[test]
        fn odd_length_is_padded() {
            assert_eq!(icmp_checksum(&[0x01]), 0xfeff);
        }

        #[test]
        fn echo_packet_checksum_matches_on_wire_value() {
            let packet = [0x08u8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01];
            assert_eq!(icmp_checksum(&packet), 0xf7fe);
        }
    }
}

#[cfg(windows)]
mod platform {
    use super::{Duration, Instant, Ipv4Addr, Ipv6Addr};
    use std::io;
    use std::mem::{self, DropGuard};
    use windows_sys::Win32::Foundation::{HANDLE, INVALID_HANDLE_VALUE};
    use windows_sys::Win32::NetworkManagement::IpHelper::{
        ICMP_ECHO_REPLY, Icmp6CreateFile, Icmp6SendEcho2, IcmpCloseHandle, IcmpCreateFile,
        IcmpSendEcho,
    };
    use windows_sys::Win32::Networking::WinSock::{AF_INET6, IN6_ADDR, IN6_ADDR_0, SOCKADDR_IN6};

    fn handle_guard(handle: HANDLE) -> DropGuard<HANDLE, impl FnOnce(HANDLE)> {
        DropGuard::new(handle, |handle| {
            // SAFETY: the guard owns the handle from IcmpCreateFile and closes it once, here.
            unsafe {
                IcmpCloseHandle(handle);
            }
        })
    }

    pub fn ping_once_ipv4(
        ip: Ipv4Addr,
        _seq: u16,
        timeout: Duration,
        _ttl: u8,
        _ident: u16,
        payload: &[u8; 24],
    ) -> io::Result<(usize, Duration)> {
        // SAFETY: the handle is checked before use and closed by its guard. The request and reply
        // buffers outlive the call, with their real lengths passed, and the reply buffer holds
        // an ICMP_ECHO_REPLY when the call reports a reply.
        unsafe {
            let handle = IcmpCreateFile();
            if handle == INVALID_HANDLE_VALUE {
                return Err(io::Error::last_os_error());
            }
            let handle = handle_guard(handle);

            let mut reply_buf = [0u8; mem::size_of::<ICMP_ECHO_REPLY>() + 24 + 8];

            let start = Instant::now();
            let num = IcmpSendEcho(
                *handle,
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
        // SAFETY: the handle is checked before use and closed by its guard. The addresses and
        // buffers outlive the call, with their real lengths passed.
        unsafe {
            let handle = Icmp6CreateFile();
            if handle == INVALID_HANDLE_VALUE {
                return Err(io::Error::last_os_error());
            }
            let handle = handle_guard(handle);

            let src_addr = SOCKADDR_IN6 {
                sin6_family: AF_INET6,
                ..Default::default()
            };

            let dst_addr = SOCKADDR_IN6 {
                sin6_family: AF_INET6,
                sin6_addr: IN6_ADDR {
                    u: IN6_ADDR_0 { Byte: ip.octets() },
                },
                ..Default::default()
            };

            // ICMPV6_ECHO_REPLY_LH (36 bytes) + payload + 8 bytes for ICMP error message + IO_STATUS_BLOCK (16 bytes on 64-bit)
            let mut reply_buf = [0u8; 36 + 24 + 8 + 32];

            let start = Instant::now();
            let num = Icmp6SendEcho2(
                *handle,
                std::ptr::null_mut(), // event = NULL
                None,                 // apcroutine = NULL
                std::ptr::null(),     // apccontext = NULL
                &raw const src_addr,
                &raw const dst_addr,
                payload.as_ptr().cast(),
                u16::try_from(payload.len()).unwrap_or(u16::MAX),
                std::ptr::null(), // requestoptions = NULL
                reply_buf.as_mut_ptr().cast(),
                u32::try_from(reply_buf.len()).unwrap_or(u32::MAX),
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
    let ip = crate::tcp::resolve_ip(destination, 0)?.ip();
    let timeout = Duration::from_millis(timeout_ms);

    let mut stats = PingStats::default();
    let mut seq: u16 = 1;

    for attempt_idx in 0..count {
        let start = Instant::now();
        let result = ping_host_once(ip, seq, timeout, ttl, ident, payload);
        let elapsed_us = micros(start.elapsed());
        let display_seq = attempt_idx + 1;

        match result {
            Ok((bytes, rtt)) => {
                stats.record(true, Some(micros(rtt)));
                let time_str = color_time_padded(micros(rtt), TIME_COLUMN_WIDTH);
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
            Err(e) => {
                stats.record(false, None);
                let msg = if e.kind() == std::io::ErrorKind::PermissionDenied {
                    format!(
                        "ICMP socket permission denied for icmp_seq {display_seq}: try running with sudo ({e})"
                    )
                } else {
                    format!(
                        "Request timeout for icmp_seq {} time={:>TIME_COLUMN_WIDTH$} TTL={} Identifier={}",
                        display_seq,
                        format_ms(elapsed_us),
                        ttl,
                        ident
                    )
                };
                let message = msg.red();
                print_with_prefix(minimal, &message);
            }
        }

        if display_seq != count {
            std::thread::sleep(Duration::from_secs(1));
        }
        seq = seq.wrapping_add(1);
    }

    print_statistics("ICMP", &stats);
    Ok(())
}
