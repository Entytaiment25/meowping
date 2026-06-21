pub struct Parser {
    pub scheme: String,
    pub host: String,
    pub port: Option<u16>,
    pub path: String,
}

impl Parser {
    pub fn parse(url: &str) -> Result<Self, &'static str> {
        let scheme_end = url.find("://");
        let (scheme, url) = match scheme_end {
            Some(end) => (&url[..end], &url[end + 3..]),
            None => {
                return Err("Missing scheme");
            }
        };

        let host_end = url.find('/').unwrap_or(url.len());

        let host_port = &url[..host_end];
        let path = if host_end < url.len() {
            &url[host_end..]
        } else {
            "/"
        };

        let mut host = host_port;
        let mut port = None;

        if host_port.starts_with('[') {
            // IPv6 bracketed notation: [::1]:port or [::1]
            if let Some(bracket_end) = host_port.find(']') {
                host = &host_port[1..bracket_end];
                let after = &host_port[bracket_end + 1..];
                if let Some(port_str) = after.strip_prefix(':') {
                    port = port_str.parse().ok();
                }
            } else {
                return Err("Invalid IPv6 address format");
            }
        } else if let Some(colon_pos) = host_port.find(':') {
            host = &host_port[..colon_pos];
            port = host_port[colon_pos + 1..].parse().ok();
        }

        if host.is_empty() {
            return Err("Invalid host");
        }

        Ok(Self {
            scheme: scheme.to_string(),
            host: host.to_string(),
            port,
            path: path.to_string(),
        })
    }

    pub fn extract_url(input: &str) -> Extracted {
        if let Ok(parsed) = Self::parse(input) {
            return Extracted::Success(parsed.host);
        }

        if Self::is_resolvable_hostname(input) {
            return Extracted::Success(input.to_string());
        }

        Extracted::Error
    }

    fn is_resolvable_hostname(hostname: &str) -> bool {
        use std::net::ToSocketAddrs;
        let socket_str = if hostname.contains(':') {
            format!("[{hostname}]:80")
        } else {
            format!("{hostname}:80")
        };
        socket_str
            .to_socket_addrs()
            .is_ok_and(|mut addrs| addrs.next().is_some())
    }
}

pub enum Extracted {
    Success(String),
    Error,
}

pub fn parse_multiple_destinations(input: &str) -> Vec<String> {
    let trimmed = input.trim();
    if trimmed.starts_with('[') && trimmed.ends_with(']') {
        trimmed[1..trimmed.len() - 1]
            .split(',')
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .collect()
    } else if trimmed.contains(',') {
        trimmed
            .split(',')
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .collect()
    } else {
        vec![trimmed.to_string()]
    }
}

pub fn parse_ports(input: &str) -> Result<Vec<u16>, String> {
    let trimmed = input.trim();
    let body = if trimmed.starts_with('[') && trimmed.ends_with(']') {
        &trimmed[1..trimmed.len() - 1]
    } else {
        trimmed
    };

    if body.trim().is_empty() {
        return Err("No ports specified".to_string());
    }

    let mut ports: Vec<u16> = Vec::new();
    for token in body.split(',') {
        let token = token.trim();
        if token.is_empty() {
            continue;
        }
        if let Some((start_s, end_s)) = token.split_once('-') {
            let start: u32 = start_s
                .trim()
                .parse()
                .map_err(|_| format!("Invalid port range start: {token}"))?;
            let end: u32 = end_s
                .trim()
                .parse()
                .map_err(|_| format!("Invalid port range end: {token}"))?;
            if end < start {
                return Err(format!("Port range end before start: {token}"));
            }
            if end > u16::MAX.into() {
                return Err(format!("Port out of range (0-65535): {token}"));
            }
            for p in start..=end {
                ports.push(u16::try_from(p).expect("range bounded by u16::MAX"));
            }
        } else {
            let p: u32 = token
                .parse()
                .map_err(|_| format!("Invalid port: {token}"))?;
            if p > u16::MAX.into() {
                return Err(format!("Port out of range (0-65535): {token}"));
            }
            ports.push(u16::try_from(p).expect("single port bounded by u16::MAX"));
        }
    }

    if ports.is_empty() {
        return Err("No ports specified".to_string());
    }

    ports.sort_unstable();
    ports.dedup();
    Ok(ports)
}
