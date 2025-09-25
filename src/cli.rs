use std::env;
use std::str::FromStr;

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
                    .map_err(|e| format!("Failed to parse value for {e}: {}", name))?;
                self.args.remove(i);
                return Ok(Some(value));
            }
        }

        let mut i = 0;
        while i < self.args.len() {
            let is_name = names.iter().any(|&name| self.args[i] == name);
            if is_name {
                if i + 1 >= self.args.len() {
                    return Err(format!("Missing value for option {}", self.args[i]));
                }
                let value_str = self.args.remove(i + 1);
                let name_taken = self.args.remove(i);
                let value = value_str
                    .parse::<T>()
                    .map_err(|e| format!("Failed to parse value for {name_taken}: {e}"))?;
                return Ok(Some(value));
            } else {
                i += 1;
            }
        }

        Ok(None)
    }
}
