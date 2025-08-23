#[cfg(target_os = "windows")]
pub mod fix_ansicolor {
    use winapi::um::consoleapi::{GetConsoleMode, SetConsoleMode};
    use winapi::um::processenv::GetStdHandle;
    use winapi::um::winbase::STD_OUTPUT_HANDLE;
    use winapi::um::wincon::ENABLE_VIRTUAL_TERMINAL_PROCESSING;

    pub fn enable_ansi_support() {
        unsafe {
            let stdout_handle = GetStdHandle(STD_OUTPUT_HANDLE);
            if stdout_handle.is_null() {
                eprintln!("Failed to get standard output handle.");
                return;
            }
            let mut mode = 0;
            if GetConsoleMode(stdout_handle, &mut mode) == 0 {
                eprintln!("Failed to get current console mode.");
                return;
            }
            if SetConsoleMode(stdout_handle, mode | ENABLE_VIRTUAL_TERMINAL_PROCESSING) == 0 {
                eprintln!("Failed to enable virtual terminal processing.");
            }
        }
    }
}

pub trait Colorize {
    fn green(&self) -> String;
    fn red(&self) -> String;
    fn blue(&self) -> String;
    fn magenta(&self) -> String;
    fn color(&self, color_code: &str) -> String;
}

impl Colorize for &str {
    fn green(&self) -> String {
        self.color("\x1b[32m")
    }

    fn red(&self) -> String {
        self.color("\x1b[31m")
    }

    fn blue(&self) -> String {
        self.color("\x1b[94m")
    }

    fn magenta(&self) -> String {
        self.color("\x1b[35m")
    }

    fn color(&self, color_code: &str) -> String {
        format!("{}{}{}", color_code, self, "\x1b[0m")
    }
}

impl Colorize for String {
    fn green(&self) -> String {
        self.as_str().green()
    }

    fn red(&self) -> String {
        self.as_str().red()
    }

    fn blue(&self) -> String {
        self.as_str().blue()
    }

    fn magenta(&self) -> String {
        self.as_str().magenta()
    }

    fn color(&self, color_code: &str) -> String {
        self.as_str().color(color_code)
    }
}

use crate::parser::Parser;
use std::fmt::Display;

#[derive(Clone, Debug, PartialEq)]
pub struct HyperLink {
    text: String,
    link: String,
}

impl HyperLink {
    pub fn new(text: impl AsRef<str>, link: impl AsRef<str>) -> Result<Self, String> {
        let text = text.as_ref().to_owned();
        let link = link.as_ref().to_owned();

        // Use the Parser to validate and parse the URL
        let parsed_url = Parser::parse(&link).map_err(|_| "Invalid URL".to_string())?;

        // Reconstruct the URL from the parsed components
        let reconstructed_url = format!(
            "{}://{}{}",
            parsed_url.scheme, parsed_url.host, parsed_url.path
        );

        Ok(Self {
            text,
            link: reconstructed_url,
        })
    }
}

impl Display for HyperLink {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let HyperLink { text, link } = self;
        write!(f, "\x1b]8;;{link}\x1b\\{text}\x1b]8;;\x1b\\")
    }
}
