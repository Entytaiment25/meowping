use url::{Host, Url};

pub enum Extracted {
    Success(String),
    Error(),
}

fn host_to_string<T: Into<String>>(host: Host<T>) -> String {
    match host {
        url::Host::Domain(domain) => domain.into(),
        url::Host::Ipv4(ipv4) => ipv4.to_string(),
        url::Host::Ipv6(ipv6) => ipv6.to_string(),
    }
}

pub fn extract_url(input: &str) -> Extracted {
    let host = Host::parse(input);

    if let Ok(host) = host {
        return Extracted::Success(host_to_string(host));
    } else {
        let url = Url::parse(input);

        if let Ok(url) = url {
            let host = url.host();

            if let Some(host) = host {
                return Extracted::Success(host_to_string(host));
            }
        }
    }

    Extracted::Error()
}
