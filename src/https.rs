use native_tls::TlsConnector;
use std::io::{ Read, Write };
use std::net::TcpStream;
use crate::parser::Parser;

pub fn get(url: &str) -> Result<String, Box<dyn std::error::Error>> {
    let parsed_url = Parser::parse(url)?;
    let host = &parsed_url.host;
    let port = parsed_url.port.unwrap_or(443);
    let path = &parsed_url.path;

    let address = if host.contains(':') {
        format!("[{}]:{}", host, port)
    } else {
        format!("{}:{}", host, port)
    };

    let stream = TcpStream::connect(address)?;
    let connector = TlsConnector::new()?;
    let mut ssl_stream = connector.connect(host, stream)?;

    let request = format!("GET {} HTTP/1.1\r\nHost: {}\r\nConnection: close\r\n\r\n", path, host);
    ssl_stream.write_all(request.as_bytes())?;

    let mut response = String::new();
    ssl_stream.read_to_string(&mut response)?;
    let body = response.split("\r\n\r\n").nth(1).ok_or("No response body")?;

    Ok(body.to_string())
}
