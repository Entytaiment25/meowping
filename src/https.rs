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

fn get_http_status(host: &str, port: u16, path: &str) -> Result<u16, Box<dyn std::error::Error>> {
    let mut stream = TcpStream::connect((host, port))?;
    let request = build_request(host, path);
    stream.write_all(request.as_bytes())?;

    let mut response = Vec::new();
    let mut buffer = [0; 4096];

    let bytes_read = stream.read(&mut buffer)?;
    response.extend_from_slice(&buffer[..bytes_read]);

    let response_str = String::from_utf8_lossy(&response);
    let status_line = response_str.lines().next().ok_or("No response status line")?;
    let status_code = status_line
        .split_whitespace()
        .nth(1)
        .ok_or("Failed to parse status code")?
        .parse::<u16>()?;

    Ok(status_code)
}

fn get_https_status(host: &str, port: u16, path: &str) -> Result<u16, Box<dyn std::error::Error>> {
    let stream = TcpStream::connect((host, port))?;
    let connector = TlsConnector::new()?;
    let mut ssl_stream = connector.connect(host, stream)?;

    let request = build_request(host, path);
    ssl_stream.write_all(request.as_bytes())?;

    let mut response = Vec::new();
    let mut buffer = [0; 4096];

    let bytes_read = ssl_stream.read(&mut buffer)?;
    response.extend_from_slice(&buffer[..bytes_read]);

    let response_str = String::from_utf8_lossy(&response);
    let status_line = response_str.lines().next().ok_or("No response status line")?;
    let status_code = status_line
        .split_whitespace()
        .nth(1)
        .ok_or("Failed to parse status code")?
        .parse::<u16>()?;

    Ok(status_code)
}

pub fn get_status(url: &str) -> Result<u16, Box<dyn std::error::Error>> {
    let parsed_url = Parser::parse(url)?;
    let host = &parsed_url.host;
    let path = &parsed_url.path;

    if url.starts_with("https://") {
        if host == "localhost" || host == "127.0.0.1" {
            return Err(
                "Cannot establish HTTPS connection: Server only supports HTTP. Use http:// instead.".into()
            );
        }
        let port = parsed_url.port.unwrap_or(443);
        get_https_status(host, port, path)
    } else {
        let port = parsed_url.port.unwrap_or(80);
        get_http_status(host, port, path)
    }
}

pub fn get(url: &str) -> Result<String, Box<dyn std::error::Error>> {
    let parsed_url = Parser::parse(url)?;
    let host = &parsed_url.host;
    let path = &parsed_url.path;

    if url.starts_with("https://") {
        let port = parsed_url.port.unwrap_or(443);
        let stream = TcpStream::connect((host.as_str(), port))?;
        let connector = TlsConnector::new()?;
        let mut ssl_stream = connector.connect(host, stream)?;

        let request = build_request(host, path);
        ssl_stream.write_all(request.as_bytes())?;

        let mut response = Vec::new();
        let mut buffer = [0; 4096];

        loop {
            match ssl_stream.read(&mut buffer) {
                Ok(0) => {
                    break;
                }
                Ok(n) => response.extend_from_slice(&buffer[..n]),
                Err(e) => {
                    return Err(e.into());
                }
            }
        }

        let response_str = String::from_utf8_lossy(&response);
        let body = response_str.split("\r\n\r\n").nth(1).ok_or("No response body")?;
        Ok(body.to_string())
    } else {
        let port = parsed_url.port.unwrap_or(80);
        let mut stream = TcpStream::connect((host.as_str(), port))?;

        let request = build_request(host, path);
        stream.write_all(request.as_bytes())?;

        let mut response = Vec::new();
        let mut buffer = [0; 4096];

        loop {
            match stream.read(&mut buffer) {
                Ok(0) => {
                    break;
                }
                Ok(n) => response.extend_from_slice(&buffer[..n]),
                Err(e) => {
                    return Err(e.into());
                }
            }
        }

        let response_str = String::from_utf8_lossy(&response);
        let body = response_str.split("\r\n\r\n").nth(1).ok_or("No response body")?;
        Ok(body.to_string())
    }
}
