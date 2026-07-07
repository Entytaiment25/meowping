use crate::parser::Parser;
use native_tls::TlsConnector;
use std::io::{Read, Write};
use std::net::TcpStream;
use std::net::ToSocketAddrs;
use std::time::Duration;

const DEFAULT_HEADERS: &[&str] = &[
    "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/115.0.0.0 Safari/537.36",
    "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    "Accept-Language: en-US,en;q=0.9",
];

fn build_request(host: &str, path: &str, extra_headers: &[String]) -> String {
    let mut req = format!("GET {path} HTTP/1.1\r\nHost: {host}\r\n");
    let headers: &[_] = if extra_headers.is_empty() {
        &DEFAULT_HEADERS
            .iter()
            .map(std::string::ToString::to_string)
            .collect::<Vec<_>>()
    } else {
        extra_headers
    };
    for h in headers {
        req.push_str(h);
        req.push_str("\r\n");
    }
    req.push_str("Connection: close\r\n\r\n");
    req
}

fn parse_http_status(response: &[u8]) -> Result<u16, Box<dyn std::error::Error>> {
    let status_line = response
        .split(|ch| *ch == b'\n')
        .next()
        .ok_or("No response status line")?;
    let status_line = status_line.strip_suffix(b"\r").unwrap_or(status_line);
    let status_line = str::from_utf8(status_line).map_err(|_| "Failed to parse status code")?;

    let status_code = status_line
        .split_whitespace()
        .nth(1)
        .ok_or("Failed to parse status code")?
        .parse::<u16>()?;

    Ok(status_code)
}

fn parse_http_body(response: &[u8]) -> Result<String, Box<dyn std::error::Error>> {
    let body_idx = response
        .windows(4)
        .position(|double_newline| double_newline == b"\r\n\r\n")
        .ok_or("No response body")?;
    Ok(String::from_utf8_lossy(&response[body_idx + 4..]).into_owned())
}

fn connect_tcp(
    host: &str,
    port: u16,
    timeout: u64,
) -> Result<TcpStream, Box<dyn std::error::Error>> {
    let addr = (host, port)
        .to_socket_addrs()?
        .next()
        .ok_or("Invalid address")?;
    Ok(TcpStream::connect_timeout(
        &addr,
        Duration::from_millis(timeout),
    )?)
}

fn read_response(mut stream: impl Read) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let mut response = Vec::new();
    stream.read_to_end(&mut response)?;
    Ok(response)
}

fn fetch_response(
    host: &str,
    port: u16,
    path: &str,
    timeout: u64,
    headers: &[String],
    tls: bool,
) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let stream = connect_tcp(host, port, timeout)?;
    let request = build_request(host, path, headers);
    if tls {
        let connector = TlsConnector::new()?;
        let mut ssl_stream = connector.connect(host, stream)?;
        ssl_stream.write_all(request.as_bytes())?;
        read_response(&mut ssl_stream)
    } else {
        let mut stream = stream;
        stream.write_all(request.as_bytes())?;
        read_response(&mut stream)
    }
}

fn is_https(url: &str, host: &str) -> Result<bool, Box<dyn std::error::Error>> {
    let https = url.starts_with("https://");
    if https && (host == "localhost" || host == "127.0.0.1") {
        return Err(
            "Cannot establish HTTPS connection: Server only supports HTTP. Use http:// instead."
                .into(),
        );
    }
    Ok(https)
}

const fn default_port(https: bool) -> u16 {
    if https { 443 } else { 80 }
}

fn fetch_url(
    url: &str,
    timeout: u64,
    headers: &[String],
) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let parsed_url = Parser::parse(url)?;
    let host = &parsed_url.host;
    let path = &parsed_url.path;
    let https = is_https(url, host)?;
    let port = parsed_url.port.unwrap_or_else(|| default_port(https));
    fetch_response(host, port, path, timeout, headers, https)
}

pub fn get_status(
    url: &str,
    timeout: u64,
    headers: &[String],
) -> Result<u16, Box<dyn std::error::Error>> {
    parse_http_status(&fetch_url(url, timeout, headers)?)
}

pub fn get(url: &str, timeout: u64) -> Result<String, Box<dyn std::error::Error>> {
    parse_http_body(&fetch_url(url, timeout, &[])?)
}
