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

        let host_end = url.find('/').unwrap_or_else(|| url.len());

        let host_port = &url[..host_end];
        let path = if host_end < url.len() {
            &url[host_end..]
        } else {
            "/"
        };

        let mut host = host_port;
        let mut port = None;

        if let Some(colon_pos) = host_port.find(':') {
            host = &host_port[..colon_pos];
            port = host_port[colon_pos + 1..].parse().ok();
        }

        if host.is_empty() {
            return Err("Invalid host");
        }

        Ok(Parser {
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
        format!("{}:80", hostname)
            .to_socket_addrs()
            .map(|mut addrs| addrs.next().is_some())
            .unwrap_or(false)
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
