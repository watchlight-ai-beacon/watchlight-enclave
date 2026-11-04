//! Append-only record of every egress attempt.
//!
//! Records are flushed one at a time rather than buffered: a sandbox killed
//! mid-run must still leave behind what it tried, and a buffer would lose
//! exactly the attempts most worth having.
//!
//! Two limits are deliberate, and both are borrowed from `wl-proxy`'s
//! `connect_gate.rs`, which learned them the hard way:
//!
//! * **Rate limiting.** An agent in a retry loop can emit thousands of
//!   identical refusals a second. Unbounded, that floods the evidence file and
//!   buries the records a reviewer came for.
//! * **Injection scanning.** A hostname reaches this process from inside the
//!   sandbox, so it is attacker-controlled input. Anything written into a
//!   record is scanned for control bytes first: a CR or LF in a logged value
//!   lets the agent forge whole records in a line-delimited file.

use std::fs::{File, OpenOptions};
use std::io::Write;
use std::path::Path;
use std::sync::Mutex;
use std::time::Instant;

/// Most records written in one run. Past this the file is closed to new
/// records so a looping agent cannot fill the disk.
const MAX_RECORDS: u64 = 10_000;

/// Most records written in any one-second window.
const MAX_PER_SECOND: u64 = 50;

struct State {
    file: File,
    written: u64,
    window_start: Instant,
    window_count: u64,
    suppressed: u64,
    suppression_noted: bool,
}

pub struct Recorder {
    state: Mutex<State>,
}

impl Recorder {
    pub fn create(path: &Path) -> std::io::Result<Self> {
        let file = OpenOptions::new().create(true).append(true).open(path)?;
        Ok(Self {
            state: Mutex::new(State {
                file,
                written: 0,
                window_start: Instant::now(),
                window_count: 0,
                suppressed: 0,
                suppression_noted: false,
            }),
        })
    }

    /// Record one attempt. Never fails the request it is describing: a guard
    /// that refused traffic because it could not write a log would be a denial
    /// of service with extra steps.
    pub fn attempt(&self, host: &str, port: u16, allowed: bool, reason: &str, protocol: &str) {
        let record = serde_json::json!({
            "ts": iso8601_now(),
            "event": "egress.attempt",
            "host": sanitize(host),
            "port": port,
            "verdict": if allowed { "allow" } else { "deny" },
            "reason": sanitize(reason),
            "protocol": protocol,
        });
        self.write(record);
    }

    fn write(&self, record: serde_json::Value) {
        let Ok(mut state) = self.state.lock() else {
            return; // poisoned: drop the record rather than panic in the data path
        };

        if state.window_start.elapsed().as_secs() >= 1 {
            state.window_start = Instant::now();
            state.window_count = 0;
        }
        let over_budget =
            state.written >= MAX_RECORDS || state.window_count >= MAX_PER_SECOND;
        if over_budget {
            state.suppressed += 1;
            if state.suppression_noted {
                return;
            }
            state.suppression_noted = true;
            // Say so once, in the file itself. A reviewer must never mistake a
            // rate-limited file for a quiet run.
            let note = serde_json::json!({
                "ts": iso8601_now(),
                "event": "egress.records_suppressed",
                "reason": if state.written >= MAX_RECORDS {
                    "per-run record limit reached"
                } else {
                    "per-second record limit reached"
                },
            });
            let _ = writeln!(state.file, "{note}");
            let _ = state.file.flush();
            return;
        }

        state.suppression_noted = false;
        state.window_count += 1;
        state.written += 1;
        let _ = writeln!(state.file, "{record}");
        let _ = state.file.flush();
    }
}

/// Strip anything that could forge a record or corrupt a log consumer.
///
/// The value came from inside the sandbox. A CR or LF would let the agent
/// write its own lines into a line-delimited evidence file; other control
/// bytes break downstream parsers. Replaced rather than dropped, so a
/// tampering attempt is visible instead of silently cleaned up.
fn sanitize(value: &str) -> String {
    let truncated: String = value.chars().take(256).collect();
    truncated
        .chars()
        .map(|c| {
            if c.is_control() || c == '\u{2028}' || c == '\u{2029}' || c == '\u{0085}' {
                '\u{FFFD}'
            } else {
                c
            }
        })
        .collect()
}

/// A UTC timestamp, without pulling in a date library for one format string.
fn iso8601_now() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    let d = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default();
    let secs = d.as_secs() as i64;
    let micros = d.subsec_micros();

    let days = secs.div_euclid(86_400);
    let tod = secs.rem_euclid(86_400);
    let (h, m, s) = (tod / 3600, (tod % 3600) / 60, tod % 60);

    // Civil-from-days (Howard Hinnant's algorithm).
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = if month <= 2 { y + 1 } else { y };

    format!("{year:04}-{month:02}-{day:02}T{h:02}:{m:02}:{s:02}.{micros:06}+00:00")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn crlf_cannot_forge_a_record() {
        let forged = sanitize("evil.example\n{\"verdict\":\"allow\"}");
        assert!(!forged.contains('\n'));
        assert!(forged.contains('\u{FFFD}'));
    }

    #[test]
    fn unicode_line_separators_are_caught_too() {
        for sneaky in ["a\u{2028}b", "a\u{2029}b", "a\u{0085}b"] {
            assert!(sanitize(sneaky).contains('\u{FFFD}'), "{sneaky:?} survived");
        }
    }

    #[test]
    fn long_values_are_truncated() {
        assert_eq!(sanitize(&"x".repeat(9_000)).chars().count(), 256);
    }

    #[test]
    fn ordinary_hostnames_survive_unchanged() {
        assert_eq!(sanitize("api.anthropic.com"), "api.anthropic.com");
    }

    #[test]
    fn timestamps_look_like_iso8601() {
        let ts = iso8601_now();
        assert_eq!(&ts[4..5], "-");
        assert!(ts.ends_with("+00:00"), "{ts}");
        assert!(ts.starts_with("20"), "{ts}");
    }
}

impl Recorder {
    /// Record a closed tunnel: how much crossed it, for how long, and why it
    /// ended. Volume is the first question after a suspected exfiltration.
    pub fn tunnel(
        &self,
        host: &str,
        port: u16,
        bytes_sent: u64,
        bytes_received: u64,
        duration_ms: u64,
        outcome: &str,
    ) {
        self.write(serde_json::json!({
            "ts": iso8601_now(),
            "event": "egress.tunnel",
            "host": sanitize(host),
            "port": port,
            "bytes_sent": bytes_sent,
            "bytes_received": bytes_received,
            "duration_ms": duration_ms,
            "outcome": outcome,
        }));
    }
}
