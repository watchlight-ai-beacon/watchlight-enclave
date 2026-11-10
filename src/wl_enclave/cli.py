"""``wl-enclave`` command-line entry point.

Three commands get a developer from nothing to a verifiable governed run::

    wl-enclave init                        # write enclave.yaml, scaffold a policy
    wl-enclave run --purpose "Fix PR #412" # run the agent in a sandbox
    wl-enclave verify runs/<id>/bundle     # check the evidence, offline

The rest are lifecycle and inspection: ``doctor``, ``ps``, ``logs``, ``kill``,
``quarantine``, ``evidence export``.
"""

from __future__ import annotations

import argparse
import json
import shutil
import sys
from pathlib import Path
from typing import Optional

from . import __version__, attestation, config, evidence, runs, signing
from .drivers import Egress, DriverError, Mount, SandboxSpec, get_driver
from .egress import (
    EGRESS_UNRECOGNISED,
    GUARD_RECORD_TYPES,
    Allowlist,
    GuardError,
    get_guard,
)

CONFIG_NAME = "enclave.yaml"

#: Where the sandbox writes its decision trail. Watchlight reads this variable.
AUDIT_DIR_IN_SANDBOX = "/evidence"


# ---------------------------------------------------------------- output ---
def _say(msg: str) -> None:
    print(f"wl-enclave: {msg}")


def _fail(msg: str, hint: Optional[str] = None) -> int:
    print(f"wl-enclave: {msg}", file=sys.stderr)
    if hint:
        print(f"            {hint}", file=sys.stderr)
    return 1


# ----------------------------------------------------------------- seal ----
def _seal(
    chain: evidence.ChainWriter,
    signer: Optional[signing.Signer],
    run_id: str,
    agent: Optional[str],
    runtime: Optional[str],
    **extra: object,
) -> Path:
    """Seal a bundle, from the one place that decides what a manifest holds.

    Four call sites used to build this payload independently and three of them
    disagreed, which was survivable while the manifest was only read. It stops
    being survivable once it is signed: a signature covers exactly these bytes,
    so a field present on one path and absent on another is a difference a
    reviewer has to explain, and the run that ended in error is the one whose
    manifest a reviewer reads most carefully.
    """
    return chain.seal(
        {"run": run_id, "agent": agent, "runtime": runtime, **extra},
        signer=signer,
    )


# ------------------------------------------------------------------ init ---
STARTER_POLICY = [
    {
        "name": "{name}-research",
        "code": 'permit(principal, action == Action::"research", resource);',
    },
    {
        "name": "{name}-no-exfiltrate",
        "code": (
            '@enforcement_effect("quarantine")\n'
            'forbid(principal, action == Action::"exfiltrate", resource);'
        ),
    },
]
"""What ``init`` scaffolds: the Watchlight policy-file format, so the same
bundle loads in the Developer Edition unchanged.

Fail-closed by construction — an intent no permit covers is denied, so intents
are added as the agent earns them rather than opened up and narrowed later. The
second entry carries a containment verb the engine accepts: it denies here, and
the containment action itself needs the governed control plane.
"""


def _cmd_init(args: argparse.Namespace) -> int:
    root = Path(args.directory).resolve()
    root.mkdir(parents=True, exist_ok=True)
    cfg_path = root / CONFIG_NAME

    if cfg_path.exists() and not args.force:
        return _fail(f"{cfg_path} already exists", "pass --force to overwrite it")

    name = args.name or root.name
    cfg_path.write_text(config.TEMPLATE.format(name=name))
    _say(f"wrote {cfg_path.relative_to(root)}")

    policy_dir = root / "policies"
    policy_dir.mkdir(exist_ok=True)
    policy_file = policy_dir / f"{name}.policy.json"
    if not policy_file.exists() or args.force:
        entries = [
            {"name": e["name"].format(name=name), "code": e["code"]}
            for e in STARTER_POLICY
        ]
        policy_file.write_text(json.dumps(entries, indent=2) + "\n")
        _say(f"wrote {policy_file.relative_to(root)}")

    # Report the runtime situation now rather than at first run.
    try:
        driver = get_driver("docker")
        problems = driver.preflight()
    except DriverError as exc:
        problems = [str(exc)]
    if problems:
        print()
        _say("the docker runtime is not ready:")
        for p in problems:
            print(f"            - {p}")
    else:
        print()
        _say("docker is ready — next: wl-enclave run")
    return 0


# ---------------------------------------------------------------- doctor ---
def _cmd_doctor(args: argparse.Namespace) -> int:
    root = Path(args.directory).resolve()
    ok = True

    cfg_path = root / CONFIG_NAME
    try:
        cfg = config.load(cfg_path)
        _say(f"config    OK   {CONFIG_NAME}")
    except config.ConfigError as exc:
        ok = False
        _say(f"config    FAIL {CONFIG_NAME}")
        for problem in exc.problems:
            print(f"                 - {problem}")
        return 0 if args.quiet else 1

    try:
        driver = get_driver(cfg.runtime)
        problems = driver.preflight()
    except DriverError as exc:
        driver, problems = None, [str(exc)]
    if problems:
        ok = False
        _say(f"runtime   FAIL {cfg.runtime}")
        for problem in problems:
            print(f"                 - {problem}")
    else:
        _say(f"runtime   OK   {cfg.runtime}")

    policies = (
        sorted(cfg.policy.glob("*.policy.json")) if cfg.policy.is_dir() else [cfg.policy]
    )
    _say(f"policy    OK   {len(policies)} file(s) in {cfg.policy.name}/")

    if cfg.egress_allow:
        try:
            Allowlist(cfg.egress_allow)
            guard_problems = get_guard("local").preflight()
        except GuardError as exc:
            guard_problems = [str(exc)]
        if guard_problems:
            ok = False
            _say(f"egress    FAIL {len(cfg.egress_allow)} host(s) allowed")
            for problem in guard_problems:
                print(f"                 - {problem}")
        else:
            _say(f"egress    OK   {len(cfg.egress_allow)} host(s) allowed, guard ready")
    else:
        _say("egress    OK   none allowed (the sandbox gets no network)")

    return 0 if ok else 1


# ------------------------------------------------------------------- run ---
def _cmd_run(args: argparse.Namespace) -> int:
    root = Path(args.directory).resolve()
    try:
        cfg = config.load(root / CONFIG_NAME)
    except config.ConfigError as exc:
        print(f"wl-enclave: {exc}", file=sys.stderr)
        return 1

    try:
        driver = get_driver(cfg.runtime)
    except DriverError as exc:
        return _fail(str(exc))

    problems = driver.preflight()
    if problems:
        return _fail(
            f"the {cfg.runtime} runtime is not ready: {problems[0]}",
            problems[1] if len(problems) > 1 else "run `wl-enclave doctor`",
        )

    # Resolved before the run opens, so a key named but unreadable fails here
    # rather than at the seal. Failing at the seal would be the worst place for
    # it: the run has already happened, and the operator asked for evidence
    # they can attribute and would get a bundle that cannot be.
    try:
        signer = signing.resolve(getattr(args, "sign_key", None))
    except signing.SigningError as exc:
        return _fail(str(exc))

    # Refused, not warned about. The workspace is mounted into the sandbox
    # writable, so a key inside it is a key the agent can read — and a key
    # holder can re-seal a truncated chain, which makes this the one mistake
    # that converts the evidence bundle into something the agent writes about
    # itself. A warning would be printed into a scrollback nobody reads at the
    # moment it matters.
    if signer is not None and signer.path is not None:
        exposed = signing.exposed_by(signer.path, [cfg.root])
        if exposed is not None:
            return _fail(
                f"the signing key {signer.path} is inside {exposed}, which is "
                f"mounted into the sandbox — the agent could read it and sign "
                f"its own evidence",
                f"move it outside the workspace; the default is "
                f"{signing.default_key_path()}",
            )

    # Built before the run opens rather than inside it: a build failure is a
    # configuration problem, and recording it as part of a run would put a
    # pre-run error in a chain that is supposed to describe an agent.
    image = cfg.agent.image
    if cfg.agent.build:
        dockerfile = cfg.root / cfg.agent.build
        if not dockerfile.is_file():
            return _fail(f"agent.build: no such file: {dockerfile}")
        if not hasattr(driver, "build_image"):
            return _fail(f"the {cfg.runtime} driver cannot build images; set agent.image")
        tag = f"wl-enclave/{cfg.agent.name}:latest"
        _say(f"building {tag}")
        try:
            image = driver.build_image(cfg.root, dockerfile, tag)
        except DriverError as exc:
            return _fail(str(exc))
    if not image:
        return _fail("agent: one of image: or build: is required")

    run = runs.create_run(root)
    purpose = args.purpose or ""
    _say(f"run {run.id}  agent={cfg.agent.name}  runtime={cfg.runtime}")
    if purpose:
        _say(f"purpose: {purpose}")

    try:
        chain = evidence.ChainWriter(run.bundle_dir)
    except evidence.BrokenChain as exc:
        return _fail(
            f"refusing to start: {exc}. A fresh run directory should hold no "
            f"chain at all, so this one was either reused or edited"
        )
    chain.append(
        "run.open",
        {
            "run": run.id,
            "agent": cfg.agent.name,
            "purpose": purpose,
            "runtime": cfg.runtime,
            "command": cfg.agent.command,
            "wl_enclave_version": __version__,
        },
    )
    # What governed this run, by content rather than by path. The workspace is
    # writable, so a run can edit the rules its successor will be held to;
    # recording the bytes means the next bundle cannot silently claim the same
    # rules as this one.
    chain.append(
        "config.attested",
        {
            "policy_path": str(cfg.policy.relative_to(cfg.root))
            if cfg.policy.is_relative_to(cfg.root)
            else str(cfg.policy),
            "egress_allow": sorted(cfg.egress_allow),
            "digests": cfg.governing_digests(),
        },
    )

    # Bring the egress guard up before the sandbox, so the sandbox has
    # somewhere to send traffic the moment it starts.
    guard = None
    egress_env: dict[str, str] = {}
    sandbox_egress = Egress.none()
    if cfg.egress_allow:
        try:
            guard = get_guard("local")
            problems = guard.preflight()
            if problems:
                return _fail(f"the egress guard is not ready: {problems[0]}")
            _say(f"egress guard: building or starting ({len(cfg.egress_allow)} rule(s))")
            endpoint = guard.start(run.id, Allowlist(cfg.egress_allow), run.egress_file)
            egress_env = endpoint.env
            sandbox_network = guard.network() or "none"
            sandbox_egress = Egress.mediated_by(
                sandbox_network,
                f"{endpoint.host}:{endpoint.port}",
                cfg.egress_allow,
            )
            chain.append(
                "egress.guard_started",
                {
                    "guard": guard.name,
                    # Which build, not just which guard. The name resolves to a
                    # binary, and a bundle that cannot say which one leaves a
                    # reviewer unable to tell whether a known guard bug was in
                    # the code that produced these records.
                    **guard.build(),
                    "endpoint": f"{endpoint.host}:{endpoint.port}",
                    "network": sandbox_network,
                    "allow": list(cfg.egress_allow),
                },
            )
            _say(f"egress guard: {endpoint.host}:{endpoint.port} on {sandbox_network}")
        except GuardError as exc:
            if guard is not None:
                guard.stop()
            # Fail rather than fall back to an open network: a run that was
            # asked to mediate egress and silently did not is worse than no run.
            chain.append("run.error", {"error": f"egress guard: {exc}"})
            _seal(chain, signer, run.id, cfg.agent.name, cfg.runtime)
            return _fail(f"egress guard: {exc}")

    def build_spec() -> SandboxSpec:
        """Built inside the try below, not before it.

        SandboxSpec.__post_init__ raises DriverError on an incoherent mount or
        egress declaration. Constructed before the try whose finally stops the
        guard, that raise leaked the guard container and its docker network,
        left the chain unsealed, and exited through a traceback — main() catches
        only KeyboardInterrupt. The spec is cheap to build and the guard is
        already running by this point, so it belongs inside the cleanup.
        """
        return SandboxSpec(
                name=f"wl-enclave-{run.id}",
            image=image,
            command=cfg.agent.command,
            env={
                **egress_env,
                # Watchlight writes its decision trail here; the bind mount below
                # is what carries it back out to the host.
                "WATCHLIGHT_AUDIT_DIR": AUDIT_DIR_IN_SANDBOX,
                "WL_ENCLAVE_RUN": run.id,
                "WL_ENCLAVE_PURPOSE": purpose,
                "WL_ENCLAVE_AGENT": cfg.agent.name,
                "WL_ENCLAVE_POLICY": "/policy",
            },
            # Binds and masks in one list, ordered so it reads as what the sandbox
            # sees: the workspace, then the hole punched in it. The workspace is
            # the project root and the run directory lives inside it, so without
            # the mask the agent could reach /work/runs/<id>/bundle and rewrite the
            # chain describing itself while the run was still going.
            mounts=[
                Mount.bind(cfg.root, "/work", read_only=False),
                *_mask_for_runs(cfg.root, cfg.root / runs.RUNS_DIR),
                Mount.bind(cfg.policy, "/policy", read_only=True),
                Mount.bind(run.evidence_dir, AUDIT_DIR_IN_SANDBOX, read_only=False),
            ],
            # Either an internal network whose only way out is the guard, or no
            # network at all. Never a default bridge.
            egress=sandbox_egress,
            memory_bytes=cfg.limits.memory_bytes,
            cpus=cfg.limits.cpus,
            pids=cfg.limits.pids,
        )

    sandbox = None

    try:
        spec = build_spec()
        sandbox = driver.provision(spec)
        run.write_meta(
            run=run.id, agent=cfg.agent.name, purpose=purpose,
            runtime=cfg.runtime, sandbox=sandbox.id, name=sandbox.name,
        )

        sandbox_attestation = driver.attest(sandbox)
        chain.append("sandbox.attested", sandbox_attestation)
        c = sandbox_attestation["constraints"]
        _say(
            f"sandbox {sandbox.id[:12]}  network={c['network_mode']}  "
            f"read-only-root={c['read_only_root']}  caps-dropped={','.join(c['cap_drop']) or 'none'}"
        )

        # Attested after the sandbox exists, because the fact being checked is
        # about the two of them together: that the sandbox's only attachment is
        # the network whose only exit is the guard. Neither half can establish
        # that alone.
        if guard is not None:
            egress_attestation = guard.attest(sandbox.id)
            chain.append("egress.attested", egress_attestation)
            if egress_attestation["route_exclusive"]:
                _say("egress     attested: the guard was the only route")
            else:
                # Loud, and in the bundle. An incomplete record that looks
                # complete is the failure this whole mechanism exists to stop.
                _say("egress     WARNING: could not attest the guard as the only route")
                for problem in egress_attestation["problems"]:
                    print(f"                 - {problem}")

        status = driver.wait(sandbox, cfg.limits.timeout_seconds)
        timed_out = status is None
        if timed_out:
            _say(f"timeout after {cfg.limits.timeout}: quarantining")
            driver.quarantine(sandbox)
            chain.append("run.contained", {"reason": "timeout", "limit": cfg.limits.timeout})

        run.log_file.write_text(driver.logs(sandbox))

        decisions, decision_account = runs.read_decisions(run.audit_file)
        # The agent authored these, so what was refused on the way in is part
        # of the record. A malformed line is not interesting on its own; a
        # thousand of them, or a truncated field, says something about the run.
        if any(decision_account.values()):
            chain.append("decision.ingest", decision_account)
        for record in decisions:
            chain.append("decision", record)

        # The guard's records go in alongside the decisions. The two layers
        # answer different questions, and a bundle is worth having because it
        # holds both: Watchlight says what authority the agent had, the guard
        # says where it actually tried to go.
        egress = []
        guard_stopped_early = False
        if guard is not None:
            from .egress.local import read_egress_records

            # Read the guard's final state before its records. A guard that
            # died mid-run leaves a record file that looks merely quiet, and
            # the single attestation was taken at provision time — too early to
            # notice. Anything the sandbox attempted after the guard went down
            # was refused by absence rather than by policy, and is absent from
            # the file rather than denied in it.
            final_state = guard.state()
            if final_state and final_state.get("guard_running") is False:
                guard_stopped_early = True
                chain.append("egress.guard_stopped", final_state)
                _say(
                    f"egress:    the guard stopped before the run ended "
                    f"(exit {final_state.get('guard_exit_code')}); its records "
                    f"are a lower bound"
                )

            # Drained before reading, so the guard's closing account — the
            # only place the true suppression total, refusal count and
            # write-error count exist — is in the file we are about to read.
            guard.drain()
            egress = read_egress_records(run.egress_file)
            for record in egress:
                # The type is chosen here, against a closed set, and is never
                # taken from the record. These records are written by another
                # process; one that could name its own type could claim to be a
                # `decision` or a `sandbox.attested` and forge a record for a
                # layer that never ran.
                declared = record.get("event")
                if declared in GUARD_RECORD_TYPES:
                    chain.append(declared, record)
                else:
                    # Kept, not dropped: an unrecognised record is itself worth
                    # seeing, and dropping it would let a writer erase evidence
                    # by malforming it.
                    chain.append(EGRESS_UNRECOGNISED, {"declared": declared, "record": record})
        # Counted over recognised records only, so the summary cannot disagree
        # with the chain: a record the chain shows as unrecognised must not be
        # tallied as an ordinary attempt in run.close.
        # Counted per record type. Summing over "every recognised record" made
        # egress_attempts the size of the file rather than a count of attempts:
        # a tunnel is a second record about an attempt already counted, a
        # saturation note names no destination at all, and a suppression note
        # is not an event. Each gets its own field so no single number has to
        # mean several things.
        def _of(kind: str) -> list:
            return [e for e in egress if e.get("event") == kind]

        attempts = _of("egress.attempt")
        egress_allowed = sum(1 for e in attempts if e.get("verdict") == "allow")
        egress_denied = sum(1 for e in attempts if e.get("verdict") == "deny")
        egress_unrecognised = sum(
            1 for e in egress if e.get("event") not in GUARD_RECORD_TYPES
        )
        suppressions = _of("egress.records_suppressed")
        records_dropped = max(
            (
                n.get("records_dropped", 0)
                for n in suppressions
                if isinstance(n.get("records_dropped"), int)
            ),
            default=0,
        )

        allows = sum(1 for d in decisions if d.get("decision") == "Allow")
        denies = sum(1 for d in decisions if d.get("decision") == "Deny")
        holds = sum(1 for d in decisions if d.get("decision") == "NeedsApproval")

        chain.append(
            "run.close",
            {
                "exit_status": status,
                "timed_out": timed_out,
                "decisions": len(decisions),
                "allow": allows, "deny": denies, "needs_approval": holds,
                "egress_attempts": len(attempts),
                # Counted separately from attempts on purpose. A malformed head
                # named no destination, so folding it into egress_attempts
                # would inflate a number a reviewer reads as "connections the
                # agent tried to make to somewhere".
                "egress_malformed": len(_of("egress.malformed")),
                "egress_tunnels": len(_of("egress.tunnel")),
                "egress_tunnel_progress_notes": len(_of("egress.tunnel_progress")),
                "egress_saturated_notes": len(_of("egress.saturated")),
                "egress_records_suppressed": len(suppressions),
                "egress_records_dropped": records_dropped,
                "egress_unrecognised": egress_unrecognised,
                "egress_guard_stopped_early": guard_stopped_early,
                "decisions_malformed": decision_account["malformed"],
                "decisions_over_cap": decision_account["dropped_over_cap"],
                "egress_allowed": egress_allowed,
                "egress_denied": egress_denied,
            },
        )
        _seal(
            chain,
            signer,
            run.id,
            cfg.agent.name,
            cfg.runtime,
            purpose=purpose,
            exit_status=status,
        )

        print()
        _say(f"decisions: {allows} allow, {denies} deny" + (f", {holds} held" if holds else ""))
        if guard is not None:
            _say(f"egress:    {egress_allowed} allow, {egress_denied} deny")
        if suppressions:
            _say(
                f"egress:    INCOMPLETE — the guard dropped {records_dropped} "
                f"record(s) it could not write"
            )
        _say(f"exit {status if status is not None else 'killed (timeout)'}")
        _say(f"bundle   {run.bundle_dir}")
        _say(f"verify   wl-enclave verify {run.bundle_dir}")
        if not decisions:
            print()
            _say(
                "no decisions recorded — the agent is not calling Watchlight. "
                "Is the SDK installed in the image, and are its tools governed?"
            )
        return 0 if (status == 0 and not timed_out) else 1

    except DriverError as exc:
        chain.append("run.error", {"error": str(exc)})
        _seal(chain, signer, run.id, cfg.agent.name, cfg.runtime)
        return _fail(str(exc))
    finally:
        # The sandbox goes first: while it is alive it can still reach the
        # guard, and removing the guard's network under a live container
        # leaves docker holding an endpoint it cannot clean up.
        if sandbox is not None and not args.keep:
            driver.teardown(sandbox)
        if guard is not None and not args.keep:
            guard.stop()


# -------------------------------------------------------------- lifecycle ---
def _cmd_ps(args: argparse.Namespace) -> int:
    root = Path(args.directory).resolve()
    rows = []
    for run in runs.iter_runs(root):
        meta = run.read_meta()
        result = evidence.verify(run.bundle_dir)
        rows.append(
            (
                run.id,
                meta.get("agent", "-"),
                str(result.records) if result.records else "-",
                # The verdict, not result.ok. ok means "chain intact", so
                # this column read "ok" for uncontained and incomplete
                # bundles — the product's central distinction missing from
                # the product's main table.
                result.verdict.upper() if result.verdict != "ok" else "ok",
                (meta.get("purpose") or "")[:40],
            )
        )
    if not rows:
        _say("no runs yet — try `wl-enclave run`")
        return 0
    print(f"{'RUN':<24} {'AGENT':<16} {'RECORDS':>7}  {'BUNDLE':<8} PURPOSE")
    for row in rows[: args.limit]:
        print(f"{row[0]:<24} {row[1]:<16} {row[2]:>7}  {row[3]:<8} {row[4]}")
    return 0


def _human_bytes(n: int) -> str:
    if not n:
        return "-"
    for unit in ("B", "kB", "MB", "GB"):
        if n < 1024 or unit == "GB":
            return f"{n:.0f} {unit}" if unit == "B" else f"{n:.1f} {unit}"
        n /= 1024.0
    return f"{n:.1f} GB"


def _cmd_hosts(args: argparse.Namespace) -> int:
    """Every host the agent reached, across runs — the question a reviewer asks.

    The evidence for this existed from the first release and there was no way
    to look at it, which left the product recording the thing it is best at and
    offering no way to read it back.
    """
    root = Path(args.directory).resolve()
    since = (args.since or "").replace("-", "")
    if since and not (len(since) == 8 and since.isdigit()):
        return _fail(
            f"--since takes a date like 2026-11-03, not {args.since!r}",
            "run ids begin with the UTC date, which is what this filters on",
        )

    hosts: dict[tuple, dict] = {}
    verified = excluded = incomplete = 0
    covers: set[str] = set()
    blocked: set[str] = set()

    for run in runs.iter_runs(root):
        if since and run.id[:8] < since:
            continue
        result = evidence.verify(run.bundle_dir)
        if result.verdict == "failed":
            # Excluded *and* counted. Dropping it silently would make this list
            # shorter and tidier than the truth, which is the one direction
            # this output must never err in — the same reason a bundle reports
            # its own gaps instead of omitting them.
            excluded += 1
            continue
        verified += 1
        if not result.complete:
            incomplete += 1
        for record in evidence.records(run.bundle_dir):
            data = record.data
            if record.type == "egress.attempt":
                key = (data.get("host"), data.get("port"), data.get("verdict"))
                entry = hosts.setdefault(key, {"n": 0, "sent": 0, "recv": 0, "ip": ""})
                entry["n"] += 1
                if data.get("resolved_ip"):
                    entry["ip"] = data["resolved_ip"]
            elif record.type == "egress.tunnel":
                # Bytes arrive on their own record, and only for connections
                # that were allowed, so they join onto the allow row.
                key = (data.get("host"), data.get("port"), "allow")
                entry = hosts.setdefault(key, {"n": 0, "sent": 0, "recv": 0, "ip": ""})
                entry["sent"] += data.get("bytes_sent") or 0
                entry["recv"] += data.get("bytes_received") or 0
            elif record.type == "egress.attested":
                covers.update(data.get("records_cover") or [])
                blocked.update(data.get("blocked_not_recorded") or [])

    if not verified and not excluded:
        _say("no runs" + (f" since {args.since}" if args.since else ""))
        return 0

    _say(
        f"runs     {verified} verified"
        + (f", {excluded} EXCLUDED because their bundles do not verify" if excluded else "")
    )
    if covers:
        # Printed with the answer, not in a footnote. "Which hosts did it
        # reach" is only answerable within what the guard can see, and a
        # reviewer reading this table is entitled to know the edge of it.
        note = ", ".join(sorted(covers)) + " only"
        if blocked:
            note += f"; {', '.join(sorted(blocked))} had no route and are not recorded"
        _say(f"coverage {note}")

    print()
    print(f"{'HOST':<28} {'PORT':>5}  {'VERDICT':<7} {'TRIES':>5} {'SENT':>9} {'RECV':>9}  LAST IP")
    for (host, port, verdict), entry in sorted(
        hosts.items(), key=lambda kv: (kv[0][2] != "deny", kv[0][0] or "")
    ):
        print(
            f"{str(host)[:28]:<28} {str(port):>5}  {str(verdict):<7} {entry['n']:>5} "
            f"{_human_bytes(entry['sent']):>9} {_human_bytes(entry['recv']):>9}  "
            f"{entry['ip'] or '-'}"
        )
    print()

    attempts = sum(e["n"] for e in hosts.values())
    _say(f"{len(hosts)} host/verdict pair(s) over {attempts} attempt(s)")
    if incomplete:
        _say(
            f"INCOMPLETE — {incomplete} run(s) report gaps in their own records, "
            f"so this list is a lower bound"
        )
    if excluded:
        _say(
            f"the {excluded} excluded run(s) reached hosts that are NOT in this "
            f"table; check them with `wl-enclave verify`"
        )
    # Non-zero when the answer is not both trustworthy and complete. A clean
    # table printed beside a failed bundle is exactly the kind of reassuring,
    # wrong summary this project exists to avoid.
    return 0 if not (excluded or incomplete) else 1


def _cmd_logs(args: argparse.Namespace) -> int:
    root = Path(args.directory).resolve()
    run = runs.find_run(root, args.run)
    if run is None:
        return _fail(f"no run matching {args.run!r}", "list them with `wl-enclave ps`")
    if not run.log_file.is_file():
        return _fail(f"run {run.id} has no logs")
    sys.stdout.write(run.log_file.read_text())
    return 0


def _cmd_kill(args: argparse.Namespace) -> int:
    """Stop a sandbox, sealing whatever evidence it already produced."""
    root = Path(args.directory).resolve()
    run = runs.find_run(root, args.run)
    if run is None:
        return _fail(f"no run matching {args.run!r}", "list them with `wl-enclave ps`")
    meta = run.read_meta()
    sandbox_id = meta.get("sandbox")
    if not sandbox_id:
        return _fail(f"run {run.id} has no recorded sandbox")

    from .drivers import Sandbox

    try:
        driver = get_driver(meta.get("runtime", "docker"))
    except DriverError as exc:
        return _fail(str(exc))
    sandbox = Sandbox(id=sandbox_id, name=meta.get("name", ""), driver=driver.name)

    # Contained first, recorded second. The chain is now verified before it is
    # extended, which means opening it can fail — and an operator reaching for
    # kill wants the agent stopped whether or not its evidence is intact.
    # Making containment wait on a successful read of the chain would hand an
    # agent that corrupted its own bundle a way to stay running.
    driver.quarantine(sandbox)
    action = "quarantined" if args.quarantine else "killed"
    try:
        chain = evidence.ChainWriter(run.bundle_dir)
    except evidence.BrokenChain as exc:
        _say(f"{action} {run.id}")
        return _fail(
            f"the bundle could not be sealed: {exc}. The sandbox was "
            f"{action}; the existing chain is left exactly as found, because "
            f"overwriting it would destroy the evidence of whatever broke it"
        )
    chain.append(
        "run.contained",
        {"reason": "operator", "command": "quarantine" if args.quarantine else "kill"},
    )
    # Resolved leniently here, unlike in `run`, and for the same reason
    # containment happens before recording: an unreadable key must not leave a
    # bundle unsealed. Sealing unsigned loses attribution, which `verify`
    # reports; refusing to seal would lose the records themselves.
    signer = None
    try:
        signer = signing.resolve(getattr(args, "sign_key", None))
    except signing.SigningError as exc:
        _say(f"sealing this bundle unsigned: {exc}")
    _seal(chain, signer, run.id, meta.get("agent"), driver.name)
    _say(f"{action} {run.id}; bundle sealed")
    return 0


# ---------------------------------------------------------------- verify ---
def _mask_for_runs(root: Path, runs_root: Path) -> list[Mount]:
    """The mask that keeps a run from seeing its own evidence, if one is needed.

    Returns a single masked mount at the workspace-relative location of
    ``runs/`` when it sits inside the directory mounted at ``/work``. When it
    does not, there is nothing to hide and the list is empty — which is why
    this returns a list rather than an optional: it splices into the mount
    list either way, and the caller does not have to care.
    """
    try:
        relative = runs_root.resolve().relative_to(root.resolve())
    except ValueError:
        return []
    return [Mount.mask(f"/work/{relative.as_posix()}")]


def _cmd_keygen(args: argparse.Namespace) -> int:
    """Create the key that signs manifests."""
    path = Path(args.path) if args.path else signing.default_key_path()
    try:
        signer = signing.generate(path, force=args.force)
    except signing.SigningError as exc:
        return _fail(str(exc))
    # "private key" and "public key id" rather than "key" and "key id": the
    # first is a file to protect, the second is a string to publish, and a
    # reader who mixes them up either pastes a private key into a ticket or
    # refuses to share the one value a reviewer needs. The wider column is
    # local to this command so the two labels line up with each other.
    _say(f"private key   {signer.path}")
    _say(f"public key id {signer.key_id}")
    print()
    _say("the private key stays in that file. it is not copied into a bundle,")
    _say("not mounted into the sandbox, and never sent anywhere.")
    print()
    _say("runs from here on will seal signed bundles.")
    _say(
        "a reviewer should pin this id: "
        f"`wl-enclave verify <bundle> --signer {signer.key_id}`"
    )
    _say(
        "without --signer, a signature only shows the manifest is unchanged — "
        "the public key travels inside the bundle, so anyone can sign one."
    )
    return 0


def _cmd_verify(args: argparse.Namespace) -> int:
    bundle = Path(args.bundle)
    if bundle.name != "bundle" and (bundle / "bundle").is_dir():
        bundle = bundle / "bundle"
    # getattr, not attribute access: these are read the same way `--sign-key`
    # is, so a caller building a Namespace by hand — which the tests and any
    # embedding do — gets the documented defaults instead of an AttributeError.
    expect_key = getattr(args, "signer", None)
    result = evidence.verify(
        bundle,
        require_signature=getattr(args, "require_signature", False) or bool(expect_key),
        expect_key=expect_key,
    )
    _say(f"bundle   {bundle}")
    _say(f"records  {result.records}")
    _say(f"head     {result.head[:16]}…")
    if result.signed:
        _say(f"signed   {result.signer_key_id}")
    # Facts first, then problems, then the verdict. Problems read as part of
    # the verdict they cause, so nothing should come between them.
    if result.egress_attested is True:
        _say("egress   attested: the guard was the sandbox's only route")
        covers = ", ".join(result.egress_covers or []) or "unstated"
        _say(f"         records cover {covers} only; other traffic was blocked, not recorded")
    elif result.egress_attested is False:
        _say("egress   NOT attested: the sandbox may have had another route")
    if result.controls:
        in_force = sum(
            1 for c in result.controls.values() if c.get("in_force") is True
        )
        _say(f"controls {in_force}/{len(result.controls)} in force")
    if result.governed_by:
        # Printed so two bundles can be compared by eye. A reviewer who sees
        # two runs claim the same policy is entitled to check that claim, and
        # this is the value that settles it.
        _say(f"governed by {result.governed_by}")
    # De-indented: this loop was nested under the governed_by check, so a
    # bundle with no config.attested record printed "controls 8/10 in force"
    # and never named the two that were not.
    if result.controls:
        for name, entry in sorted(result.controls.items()):
            if entry.get("in_force") is True:
                continue
            state = "NOT in force" if entry.get("in_force") is False else "unconfirmed"
            detail = (entry.get("detail") or "").strip()
            _say(f"         - {name}: {state}" + (f" — {detail}" if detail else ""))
    if not result.complete:
        _say("egress   INCOMPLETE — by the bundle's own account:")
        for reason in result.incomplete_reasons:
            _say(f"         - {reason}")
    for problem in result.problems:
        print(f"            - {problem}")
    _say(result.summary)
    if result.egress_attested is False:
        _say(
            "note: egress records are a lower bound for this run — anything "
            "sent by another route is not in this bundle"
        )
    # Three rungs, each with its own note, because the gap between them is
    # exactly where a reviewer over-reads a bundle. "Signed" is the word they
    # want to see and the one that establishes least.
    if result.ok and not result.signed:
        _say(
            "note: the chain is internally consistent but unsigned, so it "
            "proves nothing about who produced it"
        )
    elif result.ok and not result.signer_pinned:
        _say(
            "note: the signature shows this manifest is unchanged, not who "
            "sealed it — the public key travels inside the bundle, so anyone "
            "can produce a signed one. Pin the key you expect with "
            f"`--signer {result.signer_key_id}`"
        )
    elif result.ok:
        _say(
            "note: sealed by the key you named. A holder of that key could "
            "still have signed a truncated chain, and no witness cosigned "
            "this bundle, so this is not yet proof against the signer"
        )
    # Non-zero for an incomplete bundle as well as a broken one. A gate that
    # passed a bundle the guard itself calls incomplete would make the
    # suppression note decorative.
    return 0 if result.verdict == "ok" else 1


def _cmd_evidence_export(args: argparse.Namespace) -> int:
    root = Path(args.directory).resolve()
    run = runs.find_run(root, args.run)
    if run is None:
        return _fail(f"no run matching {args.run!r}", "list them with `wl-enclave ps`")
    result = evidence.verify(run.bundle_dir)
    # Gated on the verdict so an uncontained bundle needs --force too: a
    # bundle reporting that isolation did not hold is not an archive-clean one.
    if result.verdict != "ok" and not args.force:
        _say(f"refusing to export: bundle {result.summary}")
        # Every reason, not just integrity problems. Gating on the verdict
        # means uncontained and incomplete bundles are refused too, and those
        # carry no entries in `problems` — so printing only that list gave a
        # refusal with nothing under it.
        for problem in result.problems:
            print(f"            - {problem}")
        for reason in result.incomplete_reasons:
            print(f"            - {reason}")
        for name in attestation.failed_controls(result.controls):
            detail = (result.controls[name].get("detail") or "").strip()
            print(
                f"            - control {name} was not in force"
                + (f": {detail}" if detail else "")
            )
        return _fail("pass --force to export it anyway")
    out = Path(args.output or f"{run.id}-bundle")
    archive = shutil.make_archive(str(out), "gztar", root_dir=run.bundle_dir)
    _say(f"exported {archive}")
    return 0


# ------------------------------------------------------------------ main ---
def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="wl-enclave",
        description="Watchlight AI Enclave — a governed, isolated runtime for AI agents.",
    )
    parser.add_argument("--version", action="version", version=f"wl-enclave {__version__}")
    parser.add_argument(
        "-C", "--directory", default=".", metavar="DIR",
        help="the project directory holding enclave.yaml (default: .)",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    p_init = sub.add_parser("init", help="write enclave.yaml and scaffold a policy")
    p_init.add_argument("--name", help="agent name (default: the directory name)")
    p_init.add_argument("--force", action="store_true", help="overwrite existing files")
    p_init.set_defaults(func=_cmd_init)

    p_doctor = sub.add_parser("doctor", help="check the config, runtime and policy")
    p_doctor.add_argument("--quiet", action="store_true", help="always exit 0")
    p_doctor.set_defaults(func=_cmd_doctor)

    p_run = sub.add_parser("run", help="run the agent in a sandbox")
    p_run.add_argument("--purpose", help="why this run exists; recorded in the evidence")
    p_run.add_argument("--keep", action="store_true", help="do not remove the sandbox")
    p_run.add_argument(
        "--sign-key",
        metavar="PATH",
        help=(
            "private key to sign the manifest with "
            f"(default: ${signing.ENV_KEY}, else {signing.default_key_path()}, "
            "else seal unsigned)"
        ),
    )
    p_run.set_defaults(func=_cmd_run)

    p_keygen = sub.add_parser("keygen", help="create the key that signs manifests")
    p_keygen.add_argument(
        "--path", help=f"where to write it (default: {signing.default_key_path()})"
    )
    p_keygen.add_argument(
        "--force",
        action="store_true",
        help="replace an existing key — signatures made with the old one cannot be remade",
    )
    p_keygen.set_defaults(func=_cmd_keygen)

    p_ps = sub.add_parser("ps", help="list runs, newest first")
    p_ps.add_argument("-n", "--limit", type=int, default=20)
    p_ps.set_defaults(func=_cmd_ps)

    p_hosts = sub.add_parser(
        "hosts", help="every host the agent reached, across runs"
    )
    p_hosts.add_argument(
        "--since", metavar="DATE", help="only runs from this UTC date onward, e.g. 2026-11-03"
    )
    p_hosts.set_defaults(func=_cmd_hosts)

    p_logs = sub.add_parser("logs", help="print what a run's sandbox wrote")
    p_logs.add_argument("run", help="run id, or a unique prefix of one")
    p_logs.set_defaults(func=_cmd_logs)

    p_kill = sub.add_parser("kill", help="stop a run and seal its evidence")
    p_kill.add_argument("run")
    p_kill.set_defaults(func=_cmd_kill, quarantine=False)

    p_q = sub.add_parser("quarantine", help="kill a run immediately and seal its evidence")
    p_q.add_argument("run")
    p_q.set_defaults(func=_cmd_kill, quarantine=True)

    p_verify = sub.add_parser("verify", help="check an evidence bundle, offline")
    p_verify.add_argument("bundle", help="path to a bundle directory, or a run directory")
    p_verify.add_argument(
        "--signer",
        metavar="KEY_ID",
        help=(
            "require the manifest to be signed by this key id "
            "(the only form of this check that establishes who sealed it)"
        ),
    )
    p_verify.add_argument(
        "--require-signature",
        action="store_true",
        help="fail an unsigned bundle, without pinning which key signed it",
    )
    p_verify.set_defaults(func=_cmd_verify)

    p_ev = sub.add_parser("evidence", help="work with evidence bundles")
    ev_sub = p_ev.add_subparsers(dest="evidence_command", required=True)
    p_exp = ev_sub.add_parser("export", help="archive a run's bundle")
    p_exp.add_argument("--run", required=True)
    p_exp.add_argument("--output", help="output path without extension")
    p_exp.add_argument("--force", action="store_true", help="export even if the bundle does not verify as ok")
    p_exp.set_defaults(func=_cmd_evidence_export)

    return parser


def main(argv: Optional[list[str]] = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)
    try:
        return int(args.func(args))
    except KeyboardInterrupt:
        print()
        return _fail("interrupted")


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
