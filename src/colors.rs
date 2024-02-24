#[cfg(target_os = "windows")]
pub mod fix_ansicolor {
    use winapi::um::consoleapi::{ GetConsoleMode, SetConsoleMode };
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
    fn yellow(&self) -> String;
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

    fn yellow(&self) -> String {
        self.color("\x1b[33m")
    }

    fn blue(&self) -> String {
        self.color("\x1b[94m") // 34 is too dark
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

    fn yellow(&self) -> String {
        self.as_str().yellow()
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
