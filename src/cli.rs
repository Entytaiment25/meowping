use std::env;
use std::str::FromStr;

pub enum OptionalFlagValue {
    Missing,
    PresentWithoutValue,
    Present(String),
}

pub struct Arguments {
    args: Vec<String>,
}

impl Arguments {
    pub fn from_env() -> Self {
        let args = env::args().skip(1).collect();
        Self { args }
    }

    pub fn contains<'a, I>(&self, names: I) -> bool
    where
        I: IntoIterator<Item = &'a str>,
    {
        names
            .into_iter()
            .flat_map(|expected_arg| {
                self.args
                    .iter()
                    .map(move |found_arg| (expected_arg, found_arg.as_str()))
            })
            .filter_map(|(expected_arg, found_arg)| found_arg.strip_prefix(expected_arg))
            .any(|leftover| leftover.is_empty() || leftover.starts_with('='))
    }

    pub fn free_from_str<T>(&mut self) -> Result<T, String>
    where
        T: FromStr,
        T::Err: std::fmt::Display,
    {
        let idx = self
            .args
            .iter()
            .position(|a| !a.starts_with('-'))
            .ok_or_else(|| "Missing positional argument".to_string())?;

        let val = self.args.remove(idx);
        val.parse::<T>()
            .map_err(|e| format!("Failed to parse positional argument: {e}"))
    }

    pub fn opt_flag_with_optional_value<const N: usize>(
        &mut self,
        names: [&str; N],
    ) -> OptionalFlagValue {
        for (i, arg) in self.args.iter().enumerate() {
            for name in names {
                if let Some(rest) = arg.strip_prefix(name)
                    && let Some(value) = rest.strip_prefix('=')
                {
                    let value = value.to_string();
                    self.args.remove(i);
                    return OptionalFlagValue::Present(value);
                }
            }
        }

        let mut i = 0;
        while i < self.args.len() {
            if names.iter().any(|&name| self.args[i] == name) {
                self.args.remove(i);
                if i < self.args.len() && !self.args[i].starts_with('-') {
                    let value = self.args.remove(i);
                    return OptionalFlagValue::Present(value);
                }
                return OptionalFlagValue::PresentWithoutValue;
            }
            i += 1;
        }

        OptionalFlagValue::Missing
    }

    pub fn opt_value_from_str<T, const N: usize>(
        &mut self,
        names: [&str; N],
    ) -> Result<Option<T>, String>
    where
        T: FromStr,
        T::Err: std::fmt::Display,
    {
        for (i, arg) in self.args.iter().enumerate() {
            for name in names {
                let Some(value_with_eq) = arg.strip_prefix(name) else {
                    continue;
                };
                let Some(value_str) = value_with_eq.strip_prefix('=') else {
                    continue;
                };

                let value = value_str
                    .parse::<T>()
                    .map_err(|e| format!("Failed to parse value for {name}: {e}"))?;
                self.args.remove(i);
                return Ok(Some(value));
            }
        }

        let mut i = 0;
        while i < self.args.len() {
            let is_name = names.iter().any(|&name| self.args[i] == name);
            if is_name {
                let has_value = self
                    .args
                    .get(i + 1)
                    .is_some_and(|value| !value.starts_with('-'));
                if !has_value {
                    return Err(format!("Missing value for option {}", self.args[i]));
                }
                let value_str = self.args.remove(i + 1);
                let name_taken = self.args.remove(i);
                let value = value_str
                    .parse::<T>()
                    .map_err(|e| format!("Failed to parse value for {name_taken}: {e}"))?;
                return Ok(Some(value));
            }
            i += 1;
        }

        Ok(None)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args(list: &[&str]) -> Arguments {
        Arguments {
            args: list.iter().map(ToString::to_string).collect(),
        }
    }

    #[test]
    fn multiple_value_flags_before_destination() {
        let mut a = args(&["-t", "250", "-c", "3", "-p", "80-82", "example.com"]);
        let timeout: Option<u64> = a.opt_value_from_str(["-t", "--timeout"]).unwrap();
        assert_eq!(timeout, Some(250));
        let count: Option<usize> = a.opt_value_from_str(["-c", "--count"]).unwrap();
        assert_eq!(count, Some(3));
        let ports: Option<String> = a.opt_value_from_str(["-p", "--port"]).unwrap();
        assert_eq!(ports.as_deref(), Some("80-82"));
        let dest: String = a.free_from_str().unwrap();
        assert_eq!(dest, "example.com");
    }

    #[test]
    fn destination_before_flags_still_works() {
        let mut a = args(&["example.com", "-t", "500"]);
        let timeout: Option<u64> = a.opt_value_from_str(["-t", "--timeout"]).unwrap();
        assert_eq!(timeout, Some(500));
        let dest: String = a.free_from_str().unwrap();
        assert_eq!(dest, "example.com");
    }

    #[test]
    fn equals_form_value() {
        let mut a = args(&["--timeout=750", "1.1.1.1"]);
        let timeout: Option<u64> = a.opt_value_from_str(["-t", "--timeout"]).unwrap();
        assert_eq!(timeout, Some(750));
        let dest: String = a.free_from_str().unwrap();
        assert_eq!(dest, "1.1.1.1");
    }

    #[test]
    fn flag_is_not_consumed_as_value() {
        let mut a = args(&["-p", "-u", "example.com"]);
        assert!(a.opt_value_from_str::<String, 2>(["-p", "--port"]).is_err());
        let dest: String = a.free_from_str().unwrap();
        assert_eq!(dest, "example.com");
    }

    #[test]
    fn missing_value_at_end_is_error() {
        let mut a = args(&["example.com", "-t"]);
        assert!(a.opt_value_from_str::<u64, 2>(["-t", "--timeout"]).is_err());
    }

    #[test]
    fn bad_value_error_names_the_flag() {
        let mut a = args(&["-t", "abc", "1.1.1.1"]);
        let err = a
            .opt_value_from_str::<u64, 2>(["-t", "--timeout"])
            .unwrap_err();
        assert_eq!(
            err,
            "Failed to parse value for -t: invalid digit found in string"
        );
    }
}
