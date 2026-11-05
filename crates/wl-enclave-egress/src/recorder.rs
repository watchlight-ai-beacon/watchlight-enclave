//! Append-only record of every egress attempt.
//!
//! Records are flushed one at a time rather than buffered: a sandbox killed
//! mid-run must still leave behind what it tried, and a buffer would lose
//! exactly the attempts most worth having.
//!
//! Two limits are deliberate, and both exist because the thing being recorded
//! is controlled by the party under scrutiny:
//!
//! * **Rate limiting, with evidence and noise on separate budgets.** An agent
//!   in a retry loop can emit thousands of identical refusals a second.
//!   Unbounded, that floods the evidence file and buries the records a
//!   reviewer came for. The budgets are split because a shared one is an
//!   attack: a record the agent can generate for free must never be able to
//!   spend the budget for the records that incriminate it. A saturation note
//!   costs a bare `connect()` with no destination, while an attempt record
//!   names where the agent tried to go — so the cheap record is aggregated
//!   into its own small allowance and the expensive one keeps the whole
//!   evidence budget to itself.
//! * **Injection scanning.** A hostname reaches this process from inside the
//!   sandbox, so it is attacker-controlled input. Anything written into a
//!   record is scanned for control bytes first: a CR or LF in a logged value
//!   lets the agent forge whole records in a line-delimited file.

use std::fs::{File, OpenOptions};
use std::io::Write;
use std::net::IpAddr;
use std::path::Path;
use std::sync::Mutex;
use std::time::{Duration, Instant};

/// Most evidence records written in one run. Past this the request being
/// described is refused rather than recorded silently, so the limit bounds the
/// disk without ever buying the agent an unrecorded connection.
const MAX_RECORDS: u64 = 10_000;

/// Most evidence records written in any one-second window.
const MAX_PER_SECOND: u64 = 50;

/// Saturation notes get their own small allowance, spent from neither of the
/// budgets above. They are aggregates rather than per-connection records: the
/// interesting quantity is that the guard was full and for how many
/// connections, not which anonymous socket arrived while it was.
const MAX_SATURATION_NOTES: u64 = 120;
const SATURATION_INTERVAL: Duration = Duration::from_secs(1);

struct State {
    file: File,
    written: u64,
    window_start: Instant,
    window_count: u64,
    suppressed: u64,
    suppression_noted: bool,
    /// Connections refused for saturation, and how many of those have been
    /// accounted for in a note already. Kept apart from the evidence counters
    /// so flooding one cannot exhaust the other.
    refused: u64,
    /// Records that were within budget but did not reach the file. Counted so
    /// that a file which becomes writable again can still state the gap.
    write_errors: u64,
    refused_noted: u64,
    saturation_notes: u64,
    last_saturation: Option<Instant>,
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
                refused: 0,
                refused_noted: 0,
                write_errors: 0,
                saturation_notes: 0,
                last_saturation: None,
            }),
        })
    }

    /// Account for a connection refused because the guard was at capacity.
    ///
    /// Aggregated rather than written per connection, and spent from its own
    /// allowance rather than the evidence budget. Both properties are
    /// security-relevant, not tidiness: a payload-free `connect()` is the
    /// cheapest thing an agent can do, so a per-connection record on the
    /// shared budget let a flood of anonymous sockets exhaust the file and
    /// leave a real, allowlisted tunnel unrecorded while the bundle still
    /// read "attested".
    ///
    /// The destination is absent because the request head was never read, so
    /// the guard does not know it and must not invent one.
    pub fn saturated(&self, in_flight: usize) {
        let Ok(mut state) = self.state.lock() else {
            return;
        };
        state.refused += 1;

        let due = match state.last_saturation {
            None => true,
            Some(at) => at.elapsed() >= SATURATION_INTERVAL,
        };
        if !due || state.saturation_notes >= MAX_SATURATION_NOTES {
            return;
        }
        let since_last = state.refused - state.refused_noted;
        let record = serde_json::json!({
            "ts": iso8601_now(),
            "event": "egress.saturated",
            "in_flight": in_flight,
            "refused_since_last_note": since_last,
            "refused_total": state.refused,
            // Deliberately no "verdict": this is not an authorization outcome
            // and must not be tallied beside one. A reviewer reading "3 deny"
            // has to be able to tell three policy refusals from a full guard.
            "reason": "connection limit reached; the destination was never read",
        });
        let _ = writeln!(state.file, "{record}");
        let _ = state.file.flush();
        state.refused_noted = state.refused;
        state.saturation_notes += 1;
        state.last_saturation = Some(Instant::now());
    }

    /// Record one attempt, reporting whether it reached the file.
    ///
    /// The caller must not proceed on `false`. This inverts an earlier
    /// judgement that recording must never fail the request it describes: for
    /// a product whose claim is that a bundle cannot understate what happened,
    /// forwarding traffic that could not be recorded is the worse failure. A
    /// refused connection is a denial of service the agent can see and the
    /// bundle explains; an unrecorded one is a silent hole in the evidence.
    #[must_use]
    pub fn attempt(
        &self,
        host: &str,
        port: u16,
        allowed: bool,
        reason: &str,
        protocol: &str,
        resolved: Option<IpAddr>,
    ) -> bool {
        let mut record = serde_json::json!({
            "ts": iso8601_now(),
            "event": "egress.attempt",
            "host": sanitize(host),
            "port": port,
            "verdict": if allowed { "allow" } else { "deny" },
            "reason": sanitize(reason),
            "protocol": protocol,
        });
        // The address actually dialled, when one was. A hostname is what the
        // allowlist decides on, and it is not what the traffic went to: a name
        // can resolve differently between the decision and the next lookup, and
        // an investigator correlating this bundle against a netflow log or a
        // firewall record has only the address to join on. Omitted rather than
        // null when no address was chosen, so its presence means something.
        if let Some(ip) = resolved {
            record["resolved_ip"] = serde_json::json!(ip.to_string());
        }
        self.write(record)
    }

    /// A request that never became an attempt, because it could not be parsed.
    ///
    /// Previously these returned a status code and left no trace: a head that
    /// timed out, exceeded its size bound, or carried no request line. That is
    /// a hole of exactly the shape this guard exists to close — traffic the
    /// sandbox initiated, refused by the guard, absent from the evidence. The
    /// bundle could not distinguish "the agent made no malformed requests"
    /// from "the agent made ten thousand of them".
    ///
    /// No host is claimed, because none was parsed. Guessing one from a
    /// malformed head would put an attacker-chosen string in the field a
    /// reviewer reads as a destination.
    pub fn malformed(&self, reason: &str, bytes_read: usize) -> bool {
        self.write(serde_json::json!({
            "ts": iso8601_now(),
            "event": "egress.malformed",
            "verdict": "deny",
            "reason": sanitize(reason),
            "bytes_read": bytes_read,
            "protocol": "http",
        }))
    }

    /// Volume so far on a tunnel that is still open.
    ///
    /// A tunnel reports its byte counts when it closes, so a run killed with a
    /// transfer in flight recorded the attempt and nothing about what crossed.
    /// "How much left the sandbox" is the first question after a suspected
    /// exfiltration, and for the case where that question matters most — a run
    /// stopped mid-transfer — the answer was absent. These bound the unknown
    /// to one interval instead of the whole transfer.
    pub fn tunnel_progress(
        &self,
        host: &str,
        port: u16,
        bytes_sent: u64,
        bytes_received: u64,
        duration_ms: u64,
    ) {
        let _ = self.write(serde_json::json!({
            "ts": iso8601_now(),
            "event": "egress.tunnel_progress",
            "host": sanitize(host),
            "port": port,
            "bytes_sent": bytes_sent,
            "bytes_received": bytes_received,
            "duration_ms": duration_ms,
            "outcome": "open",
        }));
    }

    /// Write a final summary if anything was dropped.
    ///
    /// The suppressed count otherwise lives only in memory and dies with the
    /// process, leaving the bundle unable to state even the size of its own
    /// gap. Written on the way down, outside every budget, because a limit
    /// that hides its own effect is the problem rather than the control.
    pub fn finish(&self) {
        let Ok(mut state) = self.state.lock() else {
            return;
        };
        if state.suppressed == 0 && state.refused == state.refused_noted && state.write_errors == 0
        {
            return;
        }
        let record = serde_json::json!({
            "ts": iso8601_now(),
            "event": "egress.records_suppressed",
            "reason": "final account written at shutdown",
            "records_dropped": state.suppressed,
            "refused_total": state.refused,
            "refused_unnoted": state.refused - state.refused_noted,
            // A record lost to a failing file is as absent as one dropped
            // under a budget, and the two have different causes worth telling
            // apart: one means the guard was too busy, the other that its
            // evidence file stopped accepting writes.
            "write_errors": state.write_errors,
        });
        let _ = writeln!(state.file, "{record}");
        let _ = state.file.flush();
    }

    /// Returns whether the record reached the file.
    fn write(&self, record: serde_json::Value) -> bool {
        let Ok(mut state) = self.state.lock() else {
            // Poisoned: report failure rather than panic in the data path. The
            // caller refuses the request, which is the fail-closed direction.
            return false;
        };

        if state.window_start.elapsed().as_secs() >= 1 {
            state.window_start = Instant::now();
            state.window_count = 0;
        }
        let over_budget = state.written >= MAX_RECORDS || state.window_count >= MAX_PER_SECOND;
        if over_budget {
            state.suppressed += 1;
            if state.suppression_noted {
                return false;
            }
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
                "records_dropped": state.suppressed,
            });
            // Latched only if the note actually reached the file, so a failed
            // note is retried rather than silently standing in for one.
            if writeln!(state.file, "{note}").is_ok() && state.file.flush().is_ok() {
                state.suppression_noted = true;
            }
            return false;
        }

        // The write is attempted before the counters move, and its result is
        // the return value. Discarding it was fail-OPEN, and in the one
        // direction this guard exists to prevent: the caller treats `true` as
        // "recorded" and forwards the traffic, so a full or failing disk
        // yielded a policy-allowed tunnel with no record of it, in a bundle
        // that then verified as complete. Budget exhaustion was fail-closed
        // and this was not, which made the guarantee read stronger than it
        // was.
        if writeln!(state.file, "{record}").is_err() || state.file.flush().is_err() {
            state.write_errors += 1;
            return false;
        }
        state.suppression_noted = false;
        state.window_count += 1;
        state.written += 1;
        true
    }

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
        // The result is deliberately discarded: the bytes have already
        // crossed, so refusing now would protect nothing. A dropped tunnel
        // record still shows up as a suppression note, which is what tells a
        // reviewer the volume figures are incomplete.
        let _ = self.write(serde_json::json!({
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

    // Civil-from-days, Howard Hinnant's algorithm. Hand-rolled to keep the
    // dependency tree at two crates: everything linked into this process is
    // in the path of the agent's traffic, and a date library is a poor trade
    // for twenty lines a reviewer can check against the published algorithm.
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
    fn saturation_notes_cannot_exhaust_the_evidence_budget() {
        // The attack this pins down: a payload-free connect() is the cheapest
        // thing an agent can do, and when saturation notes shared the evidence
        // budget a flood of them filled the file. A real tunnel to an
        // allowlisted host then went unrecorded while the bundle still read
        // "attested, no attempts".
        let dir = std::env::temp_dir().join(format!("wl-rec-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("budget.jsonl");
        let _ = std::fs::remove_file(&path);
        let rec = Recorder::create(&path).unwrap();

        // Far more refusals than either budget would allow.
        for _ in 0..(MAX_RECORDS * 2) {
            rec.saturated(256);
        }
        // The attempt that matters must still be recordable afterwards.
        assert!(
            rec.attempt("example.com", 443, true, "allowlisted", "connect", None),
            "an attempt must still be recordable after a saturation flood"
        );

        let body = std::fs::read_to_string(&path).unwrap();
        let notes = body.matches("\"egress.saturated\"").count();
        let attempts = body.matches("\"egress.attempt\"").count();
        assert_eq!(attempts, 1, "the attempt is in the file");
        assert!(
            notes as u64 <= MAX_SATURATION_NOTES,
            "{notes} notes written, cap is {MAX_SATURATION_NOTES}"
        );
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn an_unrecordable_attempt_reports_failure_so_the_caller_can_refuse() {
        let dir = std::env::temp_dir().join(format!("wl-rec2-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("full.jsonl");
        let _ = std::fs::remove_file(&path);
        let rec = Recorder::create(&path).unwrap();

        // Spend the per-second window on real attempts.
        let mut recorded = 0;
        for _ in 0..MAX_PER_SECOND {
            if rec.attempt("example.com", 443, true, "allowlisted", "connect", None) {
                recorded += 1;
            }
        }
        assert_eq!(recorded as u64, MAX_PER_SECOND);
        // The next one cannot be written, and must say so rather than
        // returning quietly while the caller forwards the traffic.
        assert!(
            !rec.attempt("example.com", 443, true, "allowlisted", "connect", None),
            "an attempt over budget must report failure"
        );
        assert!(std::fs::read_to_string(&path)
            .unwrap()
            .contains("egress.records_suppressed"));
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn timestamps_look_like_iso8601() {
        let ts = iso8601_now();
        assert_eq!(&ts[4..5], "-");
        assert!(ts.ends_with("+00:00"), "{ts}");
        assert!(ts.starts_with("20"), "{ts}");
    }

    /// A fresh directory per test, named so two tests cannot collide.
    fn scratch(tag: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!("wl-rec-{tag}-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("egress.jsonl");
        let _ = std::fs::remove_file(&path);
        path
    }

    #[test]
    fn the_resolved_address_is_recorded_only_when_one_was_chosen() {
        // Its absence is information: it means the guard never picked an
        // address, so there is nothing to join against a firewall log.
        let path = scratch("resolved");
        let rec = Recorder::create(&path).unwrap();

        assert!(rec.attempt(
            "example.com",
            443,
            true,
            "allowlisted",
            "connect",
            Some("203.0.113.7".parse().unwrap()),
        ));
        assert!(rec.attempt(
            "blocked.test",
            443,
            false,
            "not allowlisted",
            "connect",
            None
        ));

        let body = std::fs::read_to_string(&path).unwrap();
        let lines: Vec<&str> = body.lines().collect();
        assert!(lines[0].contains(r#""resolved_ip":"203.0.113.7""#));
        assert!(
            !lines[1].contains("resolved_ip"),
            "a record with no chosen address must omit the field, not carry a null"
        );
    }

    #[test]
    fn a_request_that_could_not_be_parsed_is_still_recorded() {
        // The hole this closes: a head that timed out or carried no request
        // line got a status code and left no trace, so the bundle could not
        // tell "no malformed requests" from "ten thousand of them".
        let path = scratch("malformed");
        let rec = Recorder::create(&path).unwrap();

        assert!(rec.malformed("request head timed out", 0));

        let body = std::fs::read_to_string(&path).unwrap();
        assert!(body.contains(r#""egress.malformed""#));
        assert!(body.contains(r#""verdict":"deny""#));
        assert!(
            !body.contains(r#""host""#),
            "no host was parsed, so none may be claimed: the field a reviewer \
             reads as a destination must not carry an attacker-chosen string"
        );
    }

    #[test]
    fn an_open_tunnel_reports_volume_before_it_closes() {
        // So a run killed mid-transfer records what crossed, rather than only
        // that a connection was allowed.
        let path = scratch("progress");
        let rec = Recorder::create(&path).unwrap();

        rec.tunnel_progress("example.com", 443, 4096, 128, 300_000);

        let body = std::fs::read_to_string(&path).unwrap();
        assert!(body.contains(r#""egress.tunnel_progress""#));
        assert!(body.contains(r#""bytes_sent":4096"#));
        assert!(
            body.contains(r#""outcome":"open""#),
            "a progress record must not be mistakable for a closed tunnel's total"
        );
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn a_record_that_does_not_reach_the_file_reports_failure() {
        // The fail-open this closes. write() discarded the io::Result and
        // returned true, so on a full or failing disk attempt() said
        // "recorded" and the CONNECT handler forwarded the tunnel. A
        // policy-allowed egress then crossed with no record of it, in a bundle
        // that verified as complete — the exact outcome the guard exists to
        // prevent, and the opposite of what the doc comment promised.
        //
        // /dev/full accepts opens and fails every write with ENOSPC, which is
        // the cheapest honest stand-in for the real condition.
        let rec = Recorder::create(Path::new("/dev/full")).expect("open /dev/full");

        assert!(
            !rec.attempt("example.com", 443, true, "allowlisted", "connect", None),
            "an attempt whose record could not be written must report failure, \
             so the caller refuses the connection instead of forwarding it"
        );
    }
}
