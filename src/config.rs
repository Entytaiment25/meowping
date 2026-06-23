use std::fs;
use std::path::{Path, PathBuf};

pub struct Config {
    pub minimal: Option<bool>,
    pub no_asn: Option<bool>,
    pub http_headers: Vec<String>,
}

#[derive(PartialEq)]
enum Section {
    Settings,
    Headers,
}

impl Config {
    pub fn default_path() -> PathBuf {
        std::env::current_exe()
            .ok()
            .and_then(|p| p.parent().map(std::path::Path::to_path_buf))
            .unwrap_or_else(|| PathBuf::from("."))
            .join("meowping.conf")
    }

    pub fn load(path: &Path) -> Result<Self, String> {
        let content = fs::read_to_string(path)
            .map_err(|e| format!("Failed to read config file '{}': {}", path.display(), e))?;

        let mut minimal = None;
        let mut no_asn = None;
        let mut http_headers = Vec::new();
        let mut section = Section::Headers;

        for (i, line) in content.lines().enumerate() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            if line.eq_ignore_ascii_case("[settings]") {
                section = Section::Settings;
                continue;
            }
            if line.eq_ignore_ascii_case("[headers]") {
                section = Section::Headers;
                continue;
            }

            match section {
                Section::Settings => {
                    let (key, value) = line.split_once('=').ok_or_else(|| {
                        format!(
                            "Config line {}: expected 'key = value', got: {}",
                            i + 1,
                            line
                        )
                    })?;
                    match key.trim() {
                        "minimal" => minimal = Some(parse_bool(value.trim(), i + 1)?),
                        "no_asn" => no_asn = Some(parse_bool(value.trim(), i + 1)?),
                        unknown => {
                            return Err(format!(
                                "Config line {}: unknown setting '{}'",
                                i + 1,
                                unknown
                            ));
                        }
                    }
                }
                Section::Headers => {
                    if !line.contains(':') {
                        return Err(format!(
                            "Config line {}: expected 'Header-Name: value', got: {}",
                            i + 1,
                            line
                        ));
                    }
                    http_headers.push(line.to_string());
                }
            }
        }

        Ok(Self {
            minimal,
            no_asn,
            http_headers,
        })
    }
}

fn parse_bool(s: &str, line: usize) -> Result<bool, String> {
    match s {
        "true" | "1" | "yes" => Ok(true),
        "false" | "0" | "no" => Ok(false),
        _ => Err(format!("Config line {line}: expected true/false, got: {s}")),
    }
}
