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
        match Self::parse(input) {
            Ok(parsed) => Extracted::Success(parsed.host),
            Err(_) => Extracted::Error,
        }
    }
}

pub enum Extracted {
    Success(String),
    Error,
}
