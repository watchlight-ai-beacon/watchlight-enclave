//! Watchlight AI Enclave egress guard.
//!
//! A forward proxy that mediates a sandbox's outbound traffic: it admits only
//! the destinations the run's allowlist names, and records every attempt —
//! permitted or refused — as evidence.
//!
//! # Why a proxy at all
//!
//! A sandbox's isolation settings establish what it is *constrained to*. They
//! do not establish what it *tried*. With no network interface, a refused
//! connection leaves no trace anywhere, and the agent's own failed `connect()`
//! is not testimony anyone should accept about itself. Putting a guard in the
//! path turns "the sandbox could not reach the internet" into a per-attempt
//! record with a host, a port, a verdict and a reason.
//!
//! # Design constraints
//!
//! * **No TLS interception.** The guard needs to know *where* traffic is going,
//!   not what is in it. `CONNECT` carries the authority in plaintext before the
//!   tunnel opens, which is all the evidence requires — so the guard never
//!   holds a private key, never decrypts agent traffic, and cannot leak what it
//!   cannot see. This is a smaller blast radius than a MITM proxy by design.
//! * **Two dependencies.** This binary sits in the data path; its dependency
//!   surface is part of its threat model.
//! * **Fail closed.** Anything not understood is refused. A guard that forwards
//!   on doubt is not a guard.

mod allowlist;
mod netguard;
mod recorder;

use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Semaphore;
use tokio::time::timeout;

use allowlist::Allowlist;
use recorder::Recorder;

// --- limits ---------------------------------------------------------------
// Every one of these exists because its absence is a denial of service. A
// forward proxy is reachable by untrusted code by definition.

/// Largest request head accepted. A `CONNECT` head is tens of bytes; this is
/// generous and still bounds memory per connection.
const MAX_HEAD_BYTES: usize = 8 * 1024;

/// How long a client may take to send its request head. Without this, opening
/// sockets and sending nothing exhausts the connection budget (slowloris).
const HEAD_TIMEOUT: Duration = Duration::from_secs(10);

/// How long to spend connecting upstream before giving up.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

/// Longest a single tunnel may stay open.
const TUNNEL_MAX_LIFETIME: Duration = Duration::from_secs(3_600);

/// Concurrent connections served. Beyond this, new sockets wait rather than
/// being accepted and starved, which keeps file descriptors bounded.
const MAX_CONNECTIONS: usize = 256;

struct Guard {
    allowlist: Allowlist,
    recorder: Recorder,
    connections: AtomicU64,
}

#[tokio::main(flavor = "multi_thread", worker_threads = 2)]
async fn main() -> std::process::ExitCode {
    let listen = env_or("WL_EGRESS_LISTEN", "0.0.0.0:8080");
    let allow_spec = std::env::var("WL_EGRESS_ALLOW").unwrap_or_default();
    let record_path = match std::env::var("WL_EGRESS_RECORD") {
        Ok(p) => p,
        Err(_) => {
            eprintln!("wl-enclave-egress: WL_EGRESS_RECORD is required");
            return std::process::ExitCode::from(2);
        }
    };

    let allowlist = match Allowlist::parse(&allow_spec) {
        Ok(a) => a,
        Err(err) => {
            // Refuse to start on a malformed allowlist. Starting with a rule
            // silently dropped would run the agent under a boundary nobody
            // reviewed.
            eprintln!("wl-enclave-egress: {err}");
            return std::process::ExitCode::from(2);
        }
    };

    let recorder = match Recorder::create(std::path::Path::new(&record_path)) {
        Ok(r) => r,
        Err(err) => {
            eprintln!("wl-enclave-egress: cannot write {record_path}: {err}");
            return std::process::ExitCode::from(2);
        }
    };

    let listener = match TcpListener::bind(&listen).await {
        Ok(l) => l,
        Err(err) => {
            eprintln!("wl-enclave-egress: cannot bind {listen}: {err}");
            return std::process::ExitCode::from(2);
        }
    };

    eprintln!(
        "wl-enclave-egress: listening on {listen}, {} allowlist rule(s), recording to {record_path}",
        allowlist.len()
    );
    if allowlist.is_empty() {
        eprintln!("wl-enclave-egress: the allowlist is empty — every destination is refused");
    }

    let guard = Arc::new(Guard {
        allowlist,
        recorder,
        connections: AtomicU64::new(0),
    });
    let permits = Arc::new(Semaphore::new(MAX_CONNECTIONS));

    // Drain on a signal rather than dropping tunnels mid-write: the records
    // already on disk are the point of the whole run.
    let shutdown = shutdown_signal();
    tokio::pin!(shutdown);

    loop {
        tokio::select! {
            _ = &mut shutdown => {
                eprintln!(
                    "wl-enclave-egress: shutting down after {} connection(s)",
                    guard.connections.load(Ordering::Relaxed)
                );
                return std::process::ExitCode::SUCCESS;
            }
            accepted = listener.accept() => {
                let (stream, peer) = match accepted {
                    Ok(pair) => pair,
                    // One failed accept (fd exhaustion, reset) must not end the
                    // guard: the sandbox would then have no mediation at all.
                    Err(err) => { eprintln!("wl-enclave-egress: accept failed: {err}"); continue; }
                };
                // try_acquire, never await. Awaiting a permit here parks the
                // whole select!, which has two consequences worse than
                // refusing the connection: no further attempt is accepted or
                // recorded, so an agent holding MAX_CONNECTIONS idle tunnels
                // open could make its subsequent attempts vanish from the
                // bundle; and the shutdown arm stops being polled, so SIGTERM
                // is never observed and the guard is eventually killed with
                // records still buffered.
                let permit = match permits.clone().try_acquire_owned() {
                    Ok(permit) => permit,
                    Err(_) => {
                        let guard = guard.clone();
                        let in_flight = MAX_CONNECTIONS - permits.available_permits();
                        tokio::spawn(async move {
                            guard.recorder.saturated(&peer.to_string(), in_flight);
                            refuse_saturated(stream).await;
                        });
                        continue;
                    }
                };
                let guard = guard.clone();
                guard.connections.fetch_add(1, Ordering::Relaxed);
                tokio::spawn(async move {
                    let _permit = permit;
                    if let Err(err) = serve(guard, stream, peer).await {
                        eprintln!("wl-enclave-egress: {peer}: {err}");
                    }
                });
            }
        }
    }
}

/// Tell a client the guard is saturated, then drop it.
///
/// Bounded and best-effort: this path exists because the guard is already at
/// capacity, so it must not acquire anything or wait on the client.
async fn refuse_saturated(mut stream: TcpStream) {
    let _ = timeout(
        Duration::from_secs(2),
        stream.write_all(
            b"HTTP/1.1 503 Service Unavailable\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
        ),
    )
    .await;
    let _ = stream.shutdown().await;
}

async fn shutdown_signal() {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{signal, SignalKind};
        let mut term = match signal(SignalKind::terminate()) {
            Ok(s) => s,
            Err(_) => return std::future::pending().await,
        };
        tokio::select! {
            _ = tokio::signal::ctrl_c() => {}
            _ = term.recv() => {}
        }
    }
    #[cfg(not(unix))]
    {
        let _ = tokio::signal::ctrl_c().await;
    }
}

/// Serve one client connection.
async fn serve(
    guard: Arc<Guard>,
    mut client: TcpStream,
    _peer: SocketAddr,
) -> std::io::Result<()> {
    let head = match timeout(HEAD_TIMEOUT, read_head(&mut client)).await {
        Ok(Ok(head)) => head,
        Ok(Err(err)) => return Err(err),
        Err(_) => return respond(&mut client, 408, "Request Timeout").await,
    };

    let Some(request_line) = head.lines().next() else {
        return respond(&mut client, 400, "Bad Request").await;
    };
    let mut parts = request_line.split_whitespace();
    let (method, target) = (parts.next().unwrap_or(""), parts.next().unwrap_or(""));

    if !method.eq_ignore_ascii_case("CONNECT") {
        // Plaintext HTTP is refused rather than forwarded. Forwarding it would
        // mean parsing and rewriting attacker-controlled requests for no
        // evidentiary gain, since an agent that wants to be governed can use
        // TLS. Refusing is the smaller attack surface.
        guard
            .recorder
            .attempt(target, 0, false, "non-CONNECT request refused", "http");
        return respond(&mut client, 405, "Method Not Allowed").await;
    }

    // Authority-form requires an explicit port. Guessing one would mean the
    // record said a port the client never asked for.
    let Some((host, port)) = target.rsplit_once(':') else {
        guard
            .recorder
            .attempt(target, 0, false, "CONNECT target is not host:port", "connect");
        return respond(&mut client, 400, "Bad Request").await;
    };
    let Ok(port) = port.parse::<u16>() else {
        guard
            .recorder
            .attempt(host, 0, false, "CONNECT port is not a number", "connect");
        return respond(&mut client, 400, "Bad Request").await;
    };
    let host = host.trim_start_matches('[').trim_end_matches(']');

    // 1. The allowlist: is this destination named at all?
    let verdict = guard.allowlist.permits(host, port);
    if !verdict.allowed {
        guard
            .recorder
            .attempt(host, port, false, &verdict.reason, "connect");
        // The client is told only that it was refused. The reason is evidence,
        // not a reconnaissance oracle for code running inside the sandbox.
        return respond(&mut client, 403, "Forbidden").await;
    }

    // 2. Resolve, then validate the answer. Dialling by name again here would
    //    reopen the rebinding window this ordering exists to close.
    let resolved = match timeout(
        CONNECT_TIMEOUT,
        tokio::net::lookup_host((host, port)),
    )
    .await
    {
        Ok(Ok(addrs)) => addrs.collect::<Vec<_>>(),
        Ok(Err(err)) => {
            guard
                .recorder
                .attempt(host, port, false, &format!("DNS lookup failed: {err}"), "connect");
            return respond(&mut client, 502, "Bad Gateway").await;
        }
        Err(_) => {
            guard
                .recorder
                .attempt(host, port, false, "DNS lookup timed out", "connect");
            return respond(&mut client, 504, "Gateway Timeout").await;
        }
    };

    let mut target_addr = None;
    let mut refusal = None;
    for addr in &resolved {
        match netguard::check(addr.ip()) {
            Ok(()) => {
                target_addr = Some(*addr);
                break;
            }
            Err(why) => refusal = Some(why),
        }
    }

    let Some(addr) = target_addr else {
        let reason = refusal
            .map(|r| format!("allowlisted host resolved to a refused address: {}", r.reason()))
            .unwrap_or_else(|| "host did not resolve".to_string());
        guard.recorder.attempt(host, port, false, &reason, "connect");
        return respond(&mut client, 403, "Forbidden").await;
    };

    // 3. Dial the validated address.
    let upstream = match timeout(CONNECT_TIMEOUT, TcpStream::connect(addr)).await {
        Ok(Ok(s)) => s,
        Ok(Err(err)) => {
            guard
                .recorder
                .attempt(host, port, false, &format!("upstream unreachable: {err}"), "connect");
            return respond(&mut client, 502, "Bad Gateway").await;
        }
        Err(_) => {
            guard
                .recorder
                .attempt(host, port, false, "upstream connect timed out", "connect");
            return respond(&mut client, 504, "Gateway Timeout").await;
        }
    };

    guard
        .recorder
        .attempt(host, port, true, &verdict.reason, "connect");
    tunnel(guard, client, upstream, host, port).await
}

/// Relay bytes both ways until either side closes, or the lifetime cap hits.
///
/// Byte counts go into the evidence: how much left the sandbox is the first
/// question after a suspected exfiltration, and it is the one thing a tunnel
/// can report without decrypting anything.
async fn tunnel(
    guard: Arc<Guard>,
    mut client: TcpStream,
    upstream: TcpStream,
    host: &str,
    port: u16,
) -> std::io::Result<()> {
    client
        .write_all(b"HTTP/1.1 200 Connection Established\r\nProxy-Agent: wl-enclave-egress\r\n\r\n")
        .await?;

    let started = Instant::now();

    // Counted per direction rather than with `copy_bidirectional`, which
    // returns its totals only on success. A TLS client that closes abruptly —
    // the ordinary case, not the exceptional one — makes that an error, and the
    // byte counts would be reported as zero for a tunnel that carried traffic.
    // Volume is the first question after a suspected exfiltration, so it has to
    // survive an untidy close.
    let sent = Arc::new(AtomicU64::new(0));
    let received = Arc::new(AtomicU64::new(0));

    let (mut client_read, mut client_write) = client.into_split();
    let (mut upstream_read, mut upstream_write) = upstream.into_split();

    let up = pump(&mut client_read, &mut upstream_write, sent.clone());
    let down = pump(&mut upstream_read, &mut client_write, received.clone());

    let outcome = match timeout(TUNNEL_MAX_LIFETIME, async {
        // Either direction finishing ends the tunnel: once one side is done the
        // other has nobody to talk to.
        tokio::select! {
            r = up => r,
            r = down => r,
        }
    })
    .await
    {
        Ok(Ok(())) => "closed",
        Ok(Err(_)) => "error",
        Err(_) => "lifetime_exceeded",
    };

    let sent = sent.load(Ordering::Relaxed);
    let received = received.load(Ordering::Relaxed);

    guard.recorder.tunnel(
        host,
        port,
        sent,
        received,
        started.elapsed().as_millis() as u64,
        outcome,
    );
    Ok(())
}

/// Copy one direction of a tunnel, counting bytes as they pass.
///
/// The counter is updated before the write, so a byte that was read from the
/// sandbox is counted even if delivering it upstream then fails. For evidence,
/// what the agent managed to send is the interesting quantity.
async fn pump<R, W>(
    reader: &mut R,
    writer: &mut W,
    counter: Arc<AtomicU64>,
) -> std::io::Result<()>
where
    R: tokio::io::AsyncRead + Unpin,
    W: tokio::io::AsyncWrite + Unpin,
{
    let mut buf = vec![0u8; 16 * 1024];
    loop {
        let n = reader.read(&mut buf).await?;
        if n == 0 {
            let _ = writer.shutdown().await;
            return Ok(());
        }
        counter.fetch_add(n as u64, Ordering::Relaxed);
        writer.write_all(&buf[..n]).await?;
    }
}

/// Read until the end of the request head, bounded in both size and shape.
async fn read_head(client: &mut TcpStream) -> std::io::Result<String> {
    let mut buf = Vec::with_capacity(512);
    let mut byte = [0u8; 1];
    while !buf.ends_with(b"\r\n\r\n") && !buf.ends_with(b"\n\n") {
        if buf.len() >= MAX_HEAD_BYTES {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "request head exceeded the maximum size",
            ));
        }
        match client.read(&mut byte).await? {
            0 => break,
            _ => buf.push(byte[0]),
        }
    }
    // Lossy on purpose: a non-UTF-8 request head is malformed, and it must be
    // reportable rather than crash the connection handler.
    Ok(String::from_utf8_lossy(&buf).into_owned())
}

/// Send a minimal status response and close. Bodies are intentionally generic.
async fn respond(client: &mut TcpStream, status: u16, text: &str) -> std::io::Result<()> {
    let body = format!("{status} {text}\n");
    let response = format!(
        "HTTP/1.1 {status} {text}\r\n\
         Proxy-Agent: wl-enclave-egress\r\n\
         Content-Type: text/plain; charset=utf-8\r\n\
         Content-Length: {}\r\n\
         Connection: close\r\n\r\n{body}",
        body.len()
    );
    client.write_all(response.as_bytes()).await?;
    client.shutdown().await
}

fn env_or(key: &str, default: &str) -> String {
    std::env::var(key).unwrap_or_else(|_| default.to_string())
}
