//! A small, strict argument parser: positionals, `--name VALUE` options (repeatable), and
//! `--switch` flags. An option the command does not take is a usage error, never ignored.

/// The parsed arguments of one command.
#[derive(Debug, Default)]
pub(crate) struct Parsed {
    pub(crate) positional: Vec<String>,
    options: Vec<(String, String)>,
    switches: Vec<String>,
}

impl Parsed {
    /// Parse `argv` for a command taking the `valued` options and the `switches`.
    pub(crate) fn parse(
        argv: &[String],
        valued: &[&str],
        switches: &[&str],
    ) -> Result<Self, String> {
        let mut out = Self::default();
        let mut it = argv.iter();
        while let Some(a) = it.next() {
            if a == "--" {
                out.positional.extend(it.by_ref().cloned());
                break;
            }
            if let Some(name) = a.strip_prefix("--") {
                let (name, inline) = match name.split_once('=') {
                    Some((n, v)) => (n, Some(v.to_owned())),
                    None => (name, None),
                };
                if valued.contains(&name) {
                    let value = match inline {
                        Some(v) => v,
                        None => it
                            .next()
                            .cloned()
                            .ok_or_else(|| format!("--{name} needs a value"))?,
                    };
                    out.options.push((name.to_owned(), value));
                } else if switches.contains(&name) && inline.is_none() {
                    out.switches.push(name.to_owned());
                } else {
                    return Err(format!("unknown option --{name}"));
                }
            } else {
                out.positional.push(a.clone());
            }
        }
        Ok(out)
    }

    /// Every value given for `--name`, in order.
    pub(crate) fn all(&self, name: &str) -> Vec<&str> {
        self.options
            .iter()
            .filter(|(n, _)| n == name)
            .map(|(_, v)| v.as_str())
            .collect()
    }

    /// The value of `--name`; a usage error when given twice.
    pub(crate) fn one(&self, name: &str) -> Result<Option<&str>, String> {
        match self.all(name).as_slice() {
            [] => Ok(None),
            [v] => Ok(Some(v)),
            _ => Err(format!("--{name} given more than once")),
        }
    }

    /// Whether `--name` was given.
    pub(crate) fn has(&self, name: &str) -> bool {
        self.switches.iter().any(|s| s == name)
    }

    /// Exactly `n` positionals, named in `what` for the error.
    pub(crate) fn exactly(&self, n: usize, what: &str) -> Result<&[String], String> {
        if self.positional.len() == n {
            Ok(&self.positional)
        } else {
            Err(format!("expected {what}"))
        }
    }
}

#[cfg(test)]
mod tests {
    // Test code: a panic is the failure report.
    #![allow(clippy::unwrap_used)]
    use super::*;

    fn v(s: &[&str]) -> Vec<String> {
        s.iter().map(|x| (*x).to_owned()).collect()
    }

    #[test]
    fn options_switches_positionals() {
        let p = Parsed::parse(
            &v(&["a.pdf", "--password", "x", "--password=y", "--json", "b"]),
            &["password"],
            &["json"],
        )
        .unwrap();
        assert_eq!(p.positional, ["a.pdf", "b"]);
        assert_eq!(p.all("password"), ["x", "y"]);
        assert!(p.has("json"));
        assert!(p.one("password").is_err());
    }

    #[test]
    fn unknown_and_missing_values_are_errors() {
        assert!(Parsed::parse(&v(&["--nope"]), &[], &[]).is_err());
        assert!(Parsed::parse(&v(&["--password"]), &["password"], &[]).is_err());
        assert!(Parsed::parse(&v(&["--json=1"]), &[], &["json"]).is_err());
    }
}
