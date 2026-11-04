//! Which `host:port` the sandbox may reach. Everything else is refused.
//!
//! Two rules, in this order: an exact `host:port`, then a `*.` prefix that
//! matches at any depth below a domain but never the domain itself.
//!
//! The apex exclusion is the part worth reviewing. An operator who writes
//! `*.openai.com` has named the subdomains, not the site, and a matcher that
//! quietly includes the apex grants reach nobody asked for. The rule is also
//! the one a reader is most likely to "fix" without realising it is load
//! bearing, so it is asserted directly in the tests below.

/// A parsed allowlist. Empty means the sandbox may reach nothing.
#[derive(Debug, Clone, Default)]
pub struct Allowlist {
    rules: Vec<(String, u16)>,
}

/// Why a request was permitted or refused. Carried into the evidence record,
/// because "denied" without naming the rule is hard for a reviewer to act on.
#[derive(Debug, Clone)]
pub struct Verdict {
    pub allowed: bool,
    pub reason: String,
}

impl Allowlist {
    /// Parse a comma-separated `host:port` list, rejecting malformed entries.
    ///
    /// Fails loudly rather than skipping an entry: a typo that silently
    /// dropped a rule would widen or narrow the boundary without anyone
    /// noticing.
    pub fn parse(spec: &str) -> Result<Self, String> {
        let mut rules = Vec::new();
        for raw in spec.split(',') {
            let entry = raw.trim();
            if entry.is_empty() {
                continue;
            }
            let (host, port) = entry
                .rsplit_once(':')
                .ok_or_else(|| format!("{entry:?} must be host:port"))?;
            let port: u16 = port
                .parse()
                .map_err(|_| format!("{entry:?} has an invalid port"))?;
            if host.is_empty() || port == 0 {
                return Err(format!("{entry:?} must be host:port"));
            }
            if !host
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-' | b'_' | b'*'))
            {
                return Err(format!("{entry:?} has an invalid hostname"));
            }
            rules.push((host.to_ascii_lowercase(), port));
        }
        Ok(Self { rules })
    }

    pub fn is_empty(&self) -> bool {
        self.rules.is_empty()
    }

    pub fn len(&self) -> usize {
        self.rules.len()
    }

    /// Decide one attempt.
    pub fn permits(&self, host: &str, port: u16) -> Verdict {
        if self.rules.is_empty() {
            return Verdict {
                allowed: false,
                reason: "no allowlist entries; the sandbox may reach nothing".into(),
            };
        }
        // Trailing dots are legal in DNS and must not be a way around a rule.
        let host = host.trim_end_matches('.').to_ascii_lowercase();

        for (pattern, allowed_port) in &self.rules {
            if *allowed_port != port {
                continue;
            }
            if pattern == &host {
                return Verdict {
                    allowed: true,
                    reason: format!("matched {pattern}:{allowed_port}"),
                };
            }
            if let Some(suffix) = pattern.strip_prefix('*') {
                // suffix keeps its leading dot, so the apex cannot match.
                if host.ends_with(suffix) && host.len() > suffix.len() {
                    return Verdict {
                        allowed: true,
                        reason: format!("matched {pattern}:{allowed_port}"),
                    };
                }
            }
        }
        Verdict {
            allowed: false,
            reason: format!("{host}:{port} is not in the allowlist"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn list() -> Allowlist {
        Allowlist::parse("api.anthropic.com:443, *.openai.com:443").unwrap()
    }

    #[test]
    fn exact_host_and_port_is_allowed() {
        assert!(list().permits("api.anthropic.com", 443).allowed);
    }

    #[test]
    fn wildcard_matches_a_subdomain() {
        assert!(list().permits("api.openai.com", 443).allowed);
    }

    #[test]
    fn wildcard_matches_at_any_depth() {
        assert!(list().permits("a.b.openai.com", 443).allowed);
    }

    #[test]
    fn wildcard_does_not_match_the_apex() {
        // "*." must never widen to the bare domain. Getting this wrong would
        // silently admit openai.com itself to anyone who allowed only its
        // subdomains.
        assert!(!list().permits("openai.com", 443).allowed);
    }

    #[test]
    fn a_different_port_is_refused() {
        assert!(!list().permits("api.anthropic.com", 80).allowed);
    }

    #[test]
    fn an_unlisted_host_is_refused() {
        let v = list().permits("evil.example", 443);
        assert!(!v.allowed);
        assert!(v.reason.contains("not in the allowlist"));
    }

    #[test]
    fn a_trailing_dot_is_not_a_bypass() {
        assert!(list().permits("api.anthropic.com.", 443).allowed);
    }

    #[test]
    fn case_is_not_a_bypass() {
        assert!(list().permits("API.Anthropic.COM", 443).allowed);
    }

    #[test]
    fn a_suffix_lookalike_is_refused() {
        // "notopenai.com" must not match "*.openai.com".
        assert!(!list().permits("notopenai.com", 443).allowed);
    }

    #[test]
    fn an_empty_allowlist_refuses_everything() {
        let empty = Allowlist::parse("").unwrap();
        assert!(empty.is_empty());
        assert!(!empty.permits("api.anthropic.com", 443).allowed);
    }

    #[test]
    fn malformed_entries_are_refused_loudly() {
        assert!(Allowlist::parse("no-port").is_err());
        assert!(Allowlist::parse("host:0").is_err());
        assert!(Allowlist::parse("host:notaport").is_err());
        assert!(Allowlist::parse("ho st:443").is_err());
    }
}
