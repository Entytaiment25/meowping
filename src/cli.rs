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

    pub fn contains<I>(&self, names: I) -> bool
    where
        I: IntoIterator<Item = &'static str>,
    {
        let names: Vec<&str> = names.into_iter().collect();
        self.args.iter().any(|arg| {
            names
                .iter()
                .any(|&name| arg == name || arg.starts_with(&(name.to_string() + "=")))
        })
    }

    pub fn free_from_str<T>(&mut self) -> Result<T, String>
    where
        T: FromStr,
        T::Err: ToString,
    {
        if let Some((idx, _)) = self
            .args
            .iter()
            .enumerate()
            .find(|(_, a)| !a.starts_with('-'))
        {
            let val = self.args.remove(idx);
            val.parse::<T>()
                .map_err(|e| format!("Failed to parse positional argument: {}", e.to_string()))
        } else {
            Err("Missing positional argument".into())
        }
    }

    pub fn opt_value_from_str<T, const N: usize>(
        &mut self,
        names: [&'static str; N],
    ) -> Result<Option<T>, String>
    where
        T: FromStr,
        T::Err: ToString,
    {
        for (i, arg) in self.args.iter().enumerate() {
            for &name in &names {
                let prefix = format!("{}=", name);
                if arg.starts_with(&prefix) {
                    let value_str = &arg[prefix.len()..];
                    let value = value_str.parse::<T>().map_err(|e| {
                        format!("Failed to parse value for {}: {}", name, e.to_string())
                    })?;
                    self.args.remove(i);
                    return Ok(Some(value));
                }
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
                let value = value_str.parse::<T>().map_err(|e| {
                    format!(
                        "Failed to parse value for {}: {}",
                        name_taken,
                        e.to_string()
                    )
                })?;
                return Ok(Some(value));
            } else {
                i += 1;
            }
        }

        Ok(None)
    }
}
