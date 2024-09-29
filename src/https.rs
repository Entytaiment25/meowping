use openssl::ssl::{ SslConnector, SslMethod };
use std::io::{ Read, Write };
use std::net::TcpStream;

pub fn get(url: &str) -> Result<String, Box<dyn std::error::Error>> {
    let parsed_url = url::Url::parse(url)?;
    let host = parsed_url.host_str().ok_or("Invalid URL")?;
    let port = parsed_url.port_or_known_default().unwrap_or(443);
    let path = parsed_url.path();

    let stream = TcpStream::connect((host, port))?;

    let connector = SslConnector::builder(SslMethod::tls())?.build();
    let mut ssl_stream = connector.connect(host, stream)?;

    let request = format!("GET {} HTTP/1.1\r\nHost: {}\r\nConnection: close\r\n\r\n", path, host);

    ssl_stream.write_all(request.as_bytes())?;

    let mut response = String::new();
    ssl_stream.read_to_string(&mut response)?;

    let body = response.split("\r\n\r\n").nth(1).ok_or("No response body")?;

    Ok(body.to_string())
}
