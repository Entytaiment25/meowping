use crate::https;
use std::error::Error;
use std::thread::sleep;
use std::time::Duration;

pub fn perform_http_check(
    url: &str,
    timeout: u64,
    count: usize,
    minimal: bool,
) -> Result<(), Box<dyn Error>> {
    for i in 0..count {
        match check_http_status(url, minimal, timeout) {
            Ok(status) => {
                println!("{}", status);
            }
            Err(e) => {
                println!("{}", e);
            }
        }
        if i < count - 1 {
            sleep(Duration::from_secs(1));
        }
    }
    Ok(())
}

fn check_http_status(url: &str, minimal: bool, timeout: u64) -> Result<String, Box<dyn Error>> {
    match https::get_status(url, timeout) {
        Ok(status) => {
            let (status_text, is_online) = match status {
                200..=399 => ("online", true),
                400..=499 => ("online (client error)", true),
                500..=599 => ("offline (server error)", false),
                _ => ("unknown status", true),
            };

            let message = format!("{} is {}. HTTP status: {}", url, status_text, status);
            let formatted = if minimal {
                message.clone()
            } else {
                format!("{} {}", "[MEOWPING]".magenta_str(), message)
            };

            if is_online {
                Ok(formatted)
            } else {
                Err(formatted.into())
            }
        }
        Err(e) => {
            let error_str = e.to_string();
            let simplified_error = match error_str.as_str() {
                s if s.contains("address information") || s.contains("nodename nor servname") => {
                    "Failed to resolve host"
                }
                s if s.contains("timed out") || s.contains("timeout") => "Connection timed out",
                s if s.contains("refused") => "Connection refused",
                _ => &error_str,
            };

            let error_msg = if minimal {
                simplified_error.to_string()
            } else {
                format!("{} {}", "[MEOWPING]".magenta_str(), simplified_error)
            };
            Err(error_msg.into())
        }
    }
}

trait MagentaStr {
    fn magenta_str(&self) -> String;
}

impl MagentaStr for str {
    fn magenta_str(&self) -> String {
        format!("\x1b[35m{}\x1b[0m", self)
    }
}
