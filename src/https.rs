use native_tls::TlsConnector;
use std::io::{ Read, Write };
use std::net::TcpStream;
use crate::parser::Parser;

fn build_request(host: &str, path: &str) -> String {
    format!(
        "GET {} HTTP/1.1\r\n\
        Host: {}\r\n\
        User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/115.0.0.0 Safari/537.36\r\n\
        Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\r\n\
        Accept-Language: en-US,en;q=0.9\r\n\
        Connection: close\r\n\r\n",
        path,
        host
    )
}

pub fn get(url: &str) -> Result<String, Box<dyn std::error::Error>> {
    let parsed_url = Parser::parse(url)?;
    let host = &parsed_url.host;
    let port = parsed_url.port.unwrap_or(443);
    let path = &parsed_url.path;

    let stream = TcpStream::connect((host.as_str(), port))?;
    let connector = TlsConnector::new()?;
    let mut ssl_stream = connector.connect(host, stream)?;

    let request = build_request(host, path);
    ssl_stream.write_all(request.as_bytes())?;

    let mut response = String::new();
    ssl_stream.read_to_string(&mut response)?;
    let body = response.split("\r\n\r\n").nth(1).ok_or("No response body")?;

    Ok(body.to_string())
}

pub fn get_status(url: &str) -> Result<u16, Box<dyn std::error::Error>> {
    let parsed_url = Parser::parse(url)?;
    let host = &parsed_url.host;
    let port = parsed_url.port.unwrap_or(443);
    let path = &parsed_url.path;

    let stream = TcpStream::connect((host.as_str(), port))?;
    let connector = TlsConnector::new()?;
    let mut ssl_stream = connector.connect(host, stream)?;

    let request = build_request(host, path);
    ssl_stream.write_all(request.as_bytes())?;

    let mut response = String::new();
    ssl_stream.read_to_string(&mut response)?;

    let status_line = response.lines().next().ok_or("No response status line")?;
    let status_code = status_line
        .split_whitespace()
        .nth(1)
        .ok_or("Failed to parse status code")?
        .parse::<u16>()?;

    Ok(status_code)
}
