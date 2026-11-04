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

from . import __version__, config, evidence, runs
from .drivers import DriverError, Mount, SandboxSpec, get_driver
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

    chain = evidence.ChainWriter(run.bundle_dir)
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

    # Bring the egress guard up before the sandbox, so the sandbox has
    # somewhere to send traffic the moment it starts.
    guard = None
    egress_env: dict[str, str] = {}
    sandbox_network = "none"
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
            chain.append(
                "egress.guard_started",
                {
                    "guard": guard.name,
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
            chain.seal({"run": run.id, "agent": cfg.agent.name, "runtime": cfg.runtime})
            return _fail(f"egress guard: {exc}")

    spec = SandboxSpec(
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
        # The workspace is the project root, and the run directory lives inside
        # it. Without a shadow the agent could reach /work/runs/<id>/bundle and
        # rewrite the chain describing itself while the run was still going.
        shadow=_shadow_for_runs(cfg.root, cfg.root / runs.RUNS_DIR),
        mounts=[
            Mount(source=cfg.root, target="/work", read_only=False),
            Mount(source=cfg.policy, target="/policy", read_only=True),
            Mount(source=run.evidence_dir, target=AUDIT_DIR_IN_SANDBOX, read_only=False),
        ],
        # Either an internal network whose only way out is the guard, or no
        # network at all. Never a default bridge.
        network=sandbox_network,
        memory_bytes=cfg.limits.memory_bytes,
        cpus=cfg.limits.cpus,
        pids=cfg.limits.pids,
    )

    sandbox = None
    try:
        sandbox = driver.provision(spec)
        run.write_meta(
            run=run.id, agent=cfg.agent.name, purpose=purpose,
            runtime=cfg.runtime, sandbox=sandbox.id, name=sandbox.name,
        )

        attestation = driver.attest(sandbox)
        chain.append("sandbox.attested", attestation)
        c = attestation["constraints"]
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

        decisions = runs.read_decisions(run.audit_file)
        for record in decisions:
            chain.append("decision", record)

        # The guard's records go in alongside the decisions. The two layers
        # answer different questions, and a bundle is worth having because it
        # holds both: Watchlight says what authority the agent had, the guard
        # says where it actually tried to go.
        egress = []
        if guard is not None:
            from .egress.local import read_egress_records

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
        egress_allowed = sum(1 for e in egress if e.get("verdict") == "allow")
        egress_denied = sum(1 for e in egress if e.get("verdict") == "deny")

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
                "egress_attempts": len(egress),
                "egress_allowed": egress_allowed,
                "egress_denied": egress_denied,
            },
        )
        chain.seal(
            {
                "run": run.id,
                "agent": cfg.agent.name,
                "purpose": purpose,
                "runtime": cfg.runtime,
                "exit_status": status,
            }
        )

        print()
        _say(f"decisions: {allows} allow, {denies} deny" + (f", {holds} held" if holds else ""))
        if guard is not None:
            _say(f"egress:    {egress_allowed} allow, {egress_denied} deny")
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
        chain.seal({"run": run.id, "agent": cfg.agent.name, "runtime": cfg.runtime})
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
                "ok" if result.ok else "FAILED",
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

    chain = evidence.ChainWriter(run.bundle_dir)
    driver.quarantine(sandbox)
    chain.append(
        "run.contained",
        {"reason": "operator", "command": "quarantine" if args.quarantine else "kill"},
    )
    chain.seal({"run": run.id, "agent": meta.get("agent"), "runtime": driver.name})
    _say(f"{'quarantined' if args.quarantine else 'killed'} {run.id}; bundle sealed")
    return 0


# ---------------------------------------------------------------- verify ---
def _shadow_for_runs(root: Path, runs_root: Path) -> list[str]:
    """In-sandbox paths to cover so the run cannot see its own evidence.

    Returns the workspace-relative location of ``runs/`` when it sits inside
    the directory mounted at ``/work``. When it does not, there is nothing to
    hide and the list is empty.
    """
    try:
        relative = runs_root.resolve().relative_to(root.resolve())
    except ValueError:
        return []
    return [f"/work/{relative.as_posix()}"]


def _cmd_verify(args: argparse.Namespace) -> int:
    bundle = Path(args.bundle)
    if bundle.name != "bundle" and (bundle / "bundle").is_dir():
        bundle = bundle / "bundle"
    result = evidence.verify(bundle)
    _say(f"bundle   {bundle}")
    _say(f"records  {result.records}")
    _say(f"head     {result.head[:16]}…")
    # Facts first, then problems, then the verdict. Problems read as part of
    # the verdict they cause, so nothing should come between them.
    if result.egress_attested is True:
        _say("egress   attested: the guard was the sandbox's only route")
        covers = ", ".join(result.egress_covers or []) or "unstated"
        _say(f"         records cover {covers} only; other traffic was blocked, not recorded")
    elif result.egress_attested is False:
        _say("egress   NOT attested: the sandbox may have had another route")
    for problem in result.problems:
        print(f"            - {problem}")
    _say(result.summary)
    if result.egress_attested is False:
        _say(
            "note: egress records are a lower bound for this run — anything "
            "sent by another route is not in this bundle"
        )
    if result.ok and not result.signed:
        _say(
            "note: the chain is internally consistent but unsigned, so it "
            "proves nothing about who produced it"
        )
    return 0 if result.ok else 1


def _cmd_evidence_export(args: argparse.Namespace) -> int:
    root = Path(args.directory).resolve()
    run = runs.find_run(root, args.run)
    if run is None:
        return _fail(f"no run matching {args.run!r}", "list them with `wl-enclave ps`")
    result = evidence.verify(run.bundle_dir)
    if not result.ok and not args.force:
        _say(f"refusing to export: bundle {result.summary}")
        for problem in result.problems:
            print(f"            - {problem}")
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
    p_run.set_defaults(func=_cmd_run)

    p_ps = sub.add_parser("ps", help="list runs, newest first")
    p_ps.add_argument("-n", "--limit", type=int, default=20)
    p_ps.set_defaults(func=_cmd_ps)

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
    p_verify.set_defaults(func=_cmd_verify)

    p_ev = sub.add_parser("evidence", help="work with evidence bundles")
    ev_sub = p_ev.add_subparsers(dest="evidence_command", required=True)
    p_exp = ev_sub.add_parser("export", help="archive a run's bundle")
    p_exp.add_argument("--run", required=True)
    p_exp.add_argument("--output", help="output path without extension")
    p_exp.add_argument("--force", action="store_true", help="export even if verification fails")
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
