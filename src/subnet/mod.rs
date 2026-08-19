mod scan;
mod watch;

pub use scan::{ProbeKind, Subnet, perform_subnet_scan};

use std::net::{Ipv4Addr, Ipv6Addr};

#[derive(Clone, Copy)]
enum Family {
    V4,
    V6,
}

impl Family {
    const fn missing_segment(self) -> &'static str {
        match self {
            Self::V4 => "Missing IPv4 segment in subnet definition",
            Self::V6 => "Missing IPv6 segment in subnet definition",
        }
    }

    const fn prefix_range(self) -> &'static str {
        match self {
            Self::V4 => "Prefix length must be between 0 and 32",
            Self::V6 => "Prefix length must be between 0 and 128",
        }
    }

    const fn max_prefix(self) -> u8 {
        match self {
            Self::V4 => 32,
            Self::V6 => 128,
        }
    }
}

fn parse_prefix(input: &str, family: Family) -> Result<(&str, u8), &'static str> {
    let trimmed = input.trim();
    let mut parts = trimmed.split('/');
    let ip_part = parts.next().ok_or_else(|| family.missing_segment())?;
    let prefix_part = parts
        .next()
        .ok_or("Missing prefix length in subnet definition")?;

    if parts.next().is_some() {
        return Err("Too many '/' characters in subnet definition");
    }

    let prefix = prefix_part
        .parse::<u8>()
        .map_err(|_| "Invalid prefix length in subnet definition")?;

    if prefix > family.max_prefix() {
        return Err(family.prefix_range());
    }

    Ok((ip_part, prefix))
}

pub trait Word: Copy + PartialOrd {
    type Addr;
    const ZERO: Self;
    fn advance(self) -> Self;
    fn into_addr(self) -> Self::Addr;
}

impl Word for u32 {
    type Addr = Ipv4Addr;
    const ZERO: Self = 0;
    fn advance(self) -> Self {
        self.wrapping_add(1)
    }
    fn into_addr(self) -> Ipv4Addr {
        Ipv4Addr::from(self)
    }
}

impl Word for u128 {
    type Addr = Ipv6Addr;
    const ZERO: Self = 0;
    fn advance(self) -> Self {
        self.saturating_add(1)
    }
    fn into_addr(self) -> Ipv6Addr {
        Ipv6Addr::from(self)
    }
}

fn format_subnet_notation<W: Word>(network: W, prefix: u8) -> String
where
    W::Addr: std::fmt::Display,
{
    format!("{}/{}", network.into_addr(), prefix)
}

fn compute_host_count(prefix: u8, address_bits: u32) -> u128 {
    let host_bits = address_bits.saturating_sub(u32::from(prefix));
    if host_bits >= 64 {
        return u128::MAX;
    }
    let total_addresses = 1u128 << host_bits;

    if u32::from(prefix) >= address_bits - 1 {
        total_addresses
    } else {
        total_addresses.saturating_sub(2)
    }
}

#[derive(Clone, Copy, Debug)]
pub struct Ipv4Subnet {
    network: u32,
    prefix: u8,
}

impl Ipv4Subnet {
    pub fn from_str(input: &str) -> Result<Self, &'static str> {
        let (ip_part, prefix) = parse_prefix(input, Family::V4)?;

        let ip = ip_part
            .parse::<Ipv4Addr>()
            .map_err(|_| "Invalid IPv4 address in subnet definition")?;

        let mask = if prefix == 0 {
            0
        } else {
            (!0u32) << (32 - prefix)
        };
        let network = u32::from(ip) & mask;

        Ok(Self { network, prefix })
    }

    pub fn notation(self) -> String {
        format_subnet_notation(self.network, self.prefix)
    }

    pub fn host_count(self) -> u128 {
        compute_host_count(self.prefix, 32)
    }

    pub fn iter_hosts(self) -> SubnetHostIter<u32> {
        let total_addresses = 1u128 << (32 - u32::from(self.prefix));

        let network = u128::from(self.network);
        let (start, end) = if self.prefix >= 31 {
            (network, network + total_addresses - 1)
        } else {
            if total_addresses <= 2 {
                return SubnetHostIter::empty();
            }
            (network + 1, network + total_addresses - 2)
        };

        if start > end {
            return SubnetHostIter::empty();
        }

        SubnetHostIter {
            current: u32::try_from(start).expect("IPv4 subnet start address must fit in u32"),
            end: u32::try_from(end).expect("IPv4 subnet end address must fit in u32"),
            finished: false,
        }
    }
}

pub struct SubnetHostIter<W: Word> {
    current: W,
    end: W,
    finished: bool,
}

impl<W: Word> SubnetHostIter<W> {
    const fn empty() -> Self {
        Self {
            current: W::ZERO,
            end: W::ZERO,
            finished: true,
        }
    }
}

impl<W: Word> Iterator for SubnetHostIter<W> {
    type Item = W::Addr;

    fn next(&mut self) -> Option<Self::Item> {
        if self.finished {
            return None;
        }
        if self.current > self.end {
            self.finished = true;
            return None;
        }
        let addr = self.current.into_addr();
        self.current = self.current.advance();
        Some(addr)
    }
}

#[derive(Clone, Copy, Debug)]
pub struct Ipv6Subnet {
    network: u128,
    prefix: u8,
}

impl Ipv6Subnet {
    pub fn from_str(input: &str) -> Result<Self, &'static str> {
        let (ip_part, prefix) = parse_prefix(input, Family::V6)?;

        let ip = ip_part
            .parse::<Ipv6Addr>()
            .map_err(|_| "Invalid IPv6 address in subnet definition")?;

        let mask = if prefix == 0 {
            0
        } else {
            (!0u128) << (128 - prefix)
        };
        let network = u128::from(ip) & mask;

        Ok(Self { network, prefix })
    }

    pub fn notation(&self) -> String {
        format_subnet_notation(self.network, self.prefix)
    }

    pub fn host_count(&self) -> u128 {
        compute_host_count(self.prefix, 128)
    }

    pub fn iter_hosts(&self) -> SubnetHostIter<u128> {
        let host_bits = 128u32.saturating_sub(u32::from(self.prefix));

        if host_bits > 16 {
            return SubnetHostIter::empty();
        }

        let total_addresses = 1u128 << host_bits;

        let network = self.network;
        let (start, end) = if self.prefix >= 127 {
            (network, network.saturating_add(total_addresses - 1))
        } else {
            if total_addresses <= 2 {
                return SubnetHostIter::empty();
            }
            (network + 1, network.saturating_add(total_addresses - 2))
        };

        if start > end {
            return SubnetHostIter::empty();
        }

        SubnetHostIter {
            current: start,
            end,
            finished: false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn v4_from_str_masks_host_bits() {
        let s = Ipv4Subnet::from_str("192.168.1.130/24").unwrap();
        assert_eq!(s.notation(), "192.168.1.0/24");
    }

    #[test]
    fn v4_host_counts() {
        assert_eq!(
            Ipv4Subnet::from_str("10.0.0.0/24").unwrap().host_count(),
            254
        );
        assert_eq!(Ipv4Subnet::from_str("10.0.0.0/30").unwrap().host_count(), 2);
        assert_eq!(Ipv4Subnet::from_str("10.0.0.0/31").unwrap().host_count(), 2);
        assert_eq!(Ipv4Subnet::from_str("10.0.0.0/32").unwrap().host_count(), 1);
        assert_eq!(
            Ipv4Subnet::from_str("0.0.0.0/0").unwrap().host_count(),
            (1u128 << 32) - 2
        );
    }

    #[test]
    fn v4_iter_hosts_skips_network_and_broadcast() {
        let hosts: Vec<_> = Ipv4Subnet::from_str("192.168.1.0/30")
            .unwrap()
            .iter_hosts()
            .collect();
        assert_eq!(
            hosts,
            vec![Ipv4Addr::new(192, 168, 1, 1), Ipv4Addr::new(192, 168, 1, 2)]
        );
    }

    #[test]
    fn v4_iter_hosts_point_to_point_keeps_both() {
        let hosts: Vec<_> = Ipv4Subnet::from_str("10.0.0.4/31")
            .unwrap()
            .iter_hosts()
            .collect();
        assert_eq!(
            hosts,
            vec![Ipv4Addr::new(10, 0, 0, 4), Ipv4Addr::new(10, 0, 0, 5)]
        );
    }

    #[test]
    fn v4_iter_hosts_single_host() {
        let hosts: Vec<_> = Ipv4Subnet::from_str("10.0.0.7/32")
            .unwrap()
            .iter_hosts()
            .collect();
        assert_eq!(hosts, vec![Ipv4Addr::new(10, 0, 0, 7)]);
    }

    #[test]
    fn v4_from_str_errors() {
        assert!(Ipv4Subnet::from_str("192.168.1.0/33").is_err());
        assert!(Ipv4Subnet::from_str("192.168.1.0").is_err());
        assert!(Ipv4Subnet::from_str("192.168.1.0/24/24").is_err());
        assert!(Ipv4Subnet::from_str("notanip/24").is_err());
        assert!(Ipv4Subnet::from_str("192.168.1.0/abc").is_err());
    }

    #[test]
    fn v6_from_str_masks_host_bits() {
        let s = Ipv6Subnet::from_str("2001:db8::abcd/120").unwrap();
        assert_eq!(s.notation(), "2001:db8::ab00/120");
    }

    #[test]
    fn v6_host_counts() {
        assert_eq!(
            Ipv6Subnet::from_str("2001:db8::/120").unwrap().host_count(),
            254
        );
        assert_eq!(
            Ipv6Subnet::from_str("2001:db8::/112").unwrap().host_count(),
            65_534
        );
        assert_eq!(
            Ipv6Subnet::from_str("2001:db8::/127").unwrap().host_count(),
            2
        );
        assert_eq!(
            Ipv6Subnet::from_str("2001:db8::/128").unwrap().host_count(),
            1
        );
    }

    #[test]
    fn v6_iter_hosts_skips_first_and_last() {
        let hosts: Vec<_> = Ipv6Subnet::from_str("2001:db8::/126")
            .unwrap()
            .iter_hosts()
            .collect();
        let expected: Vec<Ipv6Addr> = [
            Ipv6Addr::new(0x2001, 0x0db8, 0, 0, 0, 0, 0, 1),
            Ipv6Addr::new(0x2001, 0x0db8, 0, 0, 0, 0, 0, 2),
        ]
        .into_iter()
        .collect();
        assert_eq!(hosts, expected);
    }

    #[test]
    fn v6_iter_hosts_caps_at_112() {
        assert_eq!(
            Ipv6Subnet::from_str("2001:db8::/112")
                .unwrap()
                .iter_hosts()
                .count(),
            65_534
        );
        assert_eq!(
            Ipv6Subnet::from_str("2001:db8::/111")
                .unwrap()
                .iter_hosts()
                .count(),
            0
        );
    }

    #[test]
    fn v6_from_str_errors() {
        assert!(Ipv6Subnet::from_str("2001:db8::/129").is_err());
        assert!(Ipv6Subnet::from_str("2001:db8::").is_err());
        assert!(Ipv6Subnet::from_str("notanip/64").is_err());
    }
}
