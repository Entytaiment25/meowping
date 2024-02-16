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
        self.color("\x1b[34m")
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
