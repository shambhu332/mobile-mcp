#!/usr/bin/env python3
# concolic_engine/auto_analyze.py

from __future__ import annotations

import argparse
import json
import os
import re
import shlex
import shutil
import subprocess
import sys
import time
import zipfile
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple


REPO_ROOT = Path(__file__).resolve().parents[1]
ORCHESTRATOR = REPO_ROOT / "concolic_engine" / "orchestrator.py"
PROVISION_SCRIPT = REPO_ROOT / "ci" / "provision_emulator.sh"
FRIDA_SCRIPT = REPO_ROOT / "ci" / "setup_frida_server.sh"
DEFAULT_RUN_ROOT = Path("/tmp/mobile-security-engine-runs")

PACKAGE_RE = re.compile(r"^[A-Za-z][A-Za-z0-9_]*(?:\.[A-Za-z0-9_]+)+$")
BAD_PATH_CHARS_RE = re.compile(r"[^A-Za-z0-9_.-]+")
KEYWORD_WEIGHTS: Tuple[Tuple[str, int], ...] = (
    ("java_", 100),
    ("verify", 40),
    ("check", 35),
    ("token", 35),
    ("auth", 35),
    ("pin", 35),
    ("ssl", 30),
    ("tls", 30),
    ("cert", 30),
    ("crypto", 30),
    ("encrypt", 28),
    ("decrypt", 28),
    ("sign", 28),
    ("hmac", 28),
    ("sha", 24),
    ("md5", 24),
    ("aes", 24),
    ("rsa", 24),
    ("secret", 22),
    ("license", 22),
    ("root", 18),
    ("debug", 18),
    ("frida", 18),
    ("password", 18),
    ("native", 10),
)


@dataclass(frozen=True)
class Target:
    kind: str
    value: str


@dataclass
class CommandRecord:
    command: List[str]
    returncode: int
    stdout: str = ""
    stderr: str = ""
    timed_out: bool = False
    stdout_path: Optional[str] = None
    duration_seconds: float = 0.0


@dataclass
class NativeLibrary:
    path: str
    name: str
    abi: Optional[str]
    size: int


@dataclass
class CandidateSymbol:
    library_path: str
    library_name: str
    symbol: str
    score: int
    source: str


@dataclass
class Context:
    args: argparse.Namespace
    output_dir: Path
    python_bin: str


class PipelineError(RuntimeError):
    pass


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def shell_quote_command(command: Sequence[str]) -> str:
    return " ".join(shlex.quote(str(part)) for part in command)


def clip(value: str, limit: int = 12000) -> str:
    if len(value) <= limit:
        return value
    return value[:limit] + f"\n...[truncated {len(value) - limit} chars]"


def sanitize_name(value: str) -> str:
    cleaned = BAD_PATH_CHARS_RE.sub("_", value.strip())
    return cleaned.strip("._-") or "app"


def choose_python() -> str:
    env_python = os.environ.get("PYTHON")
    if env_python:
        return env_python
    venv_python = REPO_ROOT / ".venv" / "bin" / "python"
    if venv_python.exists() and os.access(venv_python, os.X_OK):
        return str(venv_python)
    return sys.executable or "python3"


def run_command(
    command: Sequence[str],
    *,
    cwd: Optional[Path] = None,
    timeout: Optional[int] = None,
    check: bool = False,
    stdout_path: Optional[Path] = None,
) -> CommandRecord:
    started = time.monotonic()
    command_list = [str(part) for part in command]

    try:
        if stdout_path is not None:
            stdout_path.parent.mkdir(parents=True, exist_ok=True)
            with stdout_path.open("w", encoding="utf-8") as handle:
                proc = subprocess.run(
                    command_list,
                    cwd=str(cwd) if cwd else None,
                    stdout=handle,
                    stderr=subprocess.STDOUT,
                    text=True,
                    timeout=timeout,
                    check=False,
                )
            record = CommandRecord(
                command=command_list,
                returncode=proc.returncode,
                stdout_path=str(stdout_path),
                duration_seconds=time.monotonic() - started,
            )
        else:
            proc = subprocess.run(
                command_list,
                cwd=str(cwd) if cwd else None,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                timeout=timeout,
                check=False,
            )
            record = CommandRecord(
                command=command_list,
                returncode=proc.returncode,
                stdout=clip(proc.stdout or ""),
                stderr=clip(proc.stderr or ""),
                duration_seconds=time.monotonic() - started,
            )
    except subprocess.TimeoutExpired as exc:
        stdout = exc.stdout.decode("utf-8", errors="replace") if isinstance(exc.stdout, bytes) else (exc.stdout or "")
        stderr = exc.stderr.decode("utf-8", errors="replace") if isinstance(exc.stderr, bytes) else (exc.stderr or "")
        record = CommandRecord(
            command=command_list,
            returncode=124,
            stdout=clip(stdout),
            stderr=clip(stderr),
            timed_out=True,
            stdout_path=str(stdout_path) if stdout_path else None,
            duration_seconds=time.monotonic() - started,
        )

    if check and record.returncode != 0:
        raise PipelineError(
            f"Command failed ({record.returncode}): {shell_quote_command(record.command)}\n"
            f"{record.stderr or record.stdout}"
        )

    return record


def adb_command(args: argparse.Namespace, *parts: str) -> List[str]:
    command = [args.adb]
    if args.adb_serial:
        command.extend(["-s", args.adb_serial])
    command.extend(parts)
    return command


def adb(args: argparse.Namespace, *parts: str, timeout: Optional[int] = None, check: bool = False) -> CommandRecord:
    return run_command(adb_command(args, *parts), timeout=timeout, check=check)


def read_target_list(path: Path) -> List[str]:
    values: List[str] = []
    for line in path.read_text(encoding="utf-8").splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        values.append(stripped)
    return values


def add_target_from_value(targets: List[Target], value: str) -> None:
    expanded = Path(value).expanduser()
    if expanded.exists():
        if expanded.is_dir():
            for apk in sorted(expanded.rglob("*.apk")):
                targets.append(Target("apk", str(apk.resolve())))
            return

        if expanded.suffix.lower() == ".apk":
            targets.append(Target("apk", str(expanded.resolve())))
            return

        for nested in read_target_list(expanded):
            add_target_from_value(targets, nested)
        return

    if PACKAGE_RE.match(value):
        targets.append(Target("package", value))
        return

    raise PipelineError(f"Target is neither an existing APK/path nor a valid package name: {value}")


def resolve_initial_targets(args: argparse.Namespace) -> List[Target]:
    targets: List[Target] = []

    for value in args.targets:
        add_target_from_value(targets, value)

    for value in args.apk or []:
        path = Path(value).expanduser()
        if not path.exists() or path.suffix.lower() != ".apk":
            raise PipelineError(f"--apk must point to an APK file: {value}")
        targets.append(Target("apk", str(path.resolve())))

    for value in args.apk_dir or []:
        path = Path(value).expanduser()
        if not path.is_dir():
            raise PipelineError(f"--apk-dir must point to a directory: {value}")
        for apk in sorted(path.rglob("*.apk")):
            targets.append(Target("apk", str(apk.resolve())))

    for value in args.packages or []:
        if not PACKAGE_RE.match(value):
            raise PipelineError(f"Invalid package name: {value}")
        targets.append(Target("package", value))

    if args.target_list:
        for value in read_target_list(Path(args.target_list).expanduser()):
            add_target_from_value(targets, value)

    deduped: List[Target] = []
    seen = set()
    for target in targets:
        key = (target.kind, target.value)
        if key in seen:
            continue
        seen.add(key)
        deduped.append(target)

    return deduped


def installed_user_packages(args: argparse.Namespace) -> List[Target]:
    result = adb(args, "shell", "cmd", "package", "list", "packages", "-3", timeout=30, check=True)
    targets: List[Target] = []
    for line in result.stdout.splitlines():
        line = line.strip()
        if line.startswith("package:"):
            package = line.removeprefix("package:").strip()
            if PACKAGE_RE.match(package):
                targets.append(Target("package", package))
    return targets


def run_repo_script(script: Path, timeout: int) -> CommandRecord:
    return run_command(["bash", str(script)], cwd=REPO_ROOT, timeout=timeout)


def provision_environment(ctx: Context, report: Dict[str, Any]) -> None:
    setup_records: Dict[str, Any] = {}

    if ctx.args.skip_provision:
        setup_records["provision"] = {"skipped": True}
    else:
        print("[*] Provisioning emulator and proxy...")
        provision = run_repo_script(PROVISION_SCRIPT, timeout=240)
        setup_records["provision"] = asdict(provision)
        if provision.returncode != 0:
            raise PipelineError(provision.stderr or provision.stdout or "Emulator provisioning failed")
        time.sleep(5)

    if ctx.args.skip_frida:
        setup_records["frida"] = {"skipped": True}
    else:
        print("[*] Setting up Frida server...")
        attempts: List[Dict[str, Any]] = []
        last: Optional[CommandRecord] = None
        for attempt in range(1, 4):
            last = run_repo_script(FRIDA_SCRIPT, timeout=360)
            attempts.append(asdict(last))
            if last.returncode == 0:
                break
            print(f"[!] Frida setup attempt {attempt} failed; retrying after ADB settles...")
            time.sleep(6)

        setup_records["frida"] = attempts
        if last is None or last.returncode != 0:
            raise PipelineError(last.stderr if last else "Frida setup failed")

    report["environment"] = setup_records


def extract_package_from_apk(apk_path: Path) -> Optional[str]:
    aapt = shutil.which("aapt")
    if aapt:
        result = run_command([aapt, "dump", "badging", str(apk_path)], timeout=30)
        match = re.search(r"package:\s+name='([^']+)'", result.stdout)
        if match:
            return match.group(1)

    apkanalyzer = shutil.which("apkanalyzer")
    if apkanalyzer:
        result = run_command([apkanalyzer, "manifest", "application-id", str(apk_path)], timeout=30)
        package = result.stdout.strip().splitlines()[0] if result.stdout.strip() else ""
        if PACKAGE_RE.match(package):
            return package

    return None


def package_list(args: argparse.Namespace) -> set[str]:
    result = adb(args, "shell", "cmd", "package", "list", "packages", timeout=30, check=True)
    packages = set()
    for line in result.stdout.splitlines():
        line = line.strip()
        if line.startswith("package:"):
            packages.add(line.removeprefix("package:").strip())
    return packages


def install_apk(ctx: Context, apk_path: Path, before_packages: set[str]) -> Tuple[Optional[str], Dict[str, Any]]:
    if ctx.args.skip_install:
        return None, {"skipped": True}

    print(f"[*] Installing {apk_path.name}...")
    install = adb(ctx.args, "install", "-r", "-g", str(apk_path), timeout=240)
    attempts = [asdict(install)]
    if install.returncode != 0 and "INSTALL_FAILED_TEST_ONLY" in f"{install.stdout}\n{install.stderr}":
        install = adb(ctx.args, "install", "-r", "-g", "-t", str(apk_path), timeout=240)
        attempts.append(asdict(install))

    if install.returncode != 0:
        return None, {"attempts": attempts, "error": "adb install failed"}

    after_packages = package_list(ctx.args)
    added = sorted(after_packages - before_packages)
    package = added[0] if len(added) == 1 else None
    return package, {"attempts": attempts, "detected_new_packages": added}


def pull_package_apk(ctx: Context, package_name: str, dest_dir: Path) -> Optional[Path]:
    result = adb(ctx.args, "shell", "pm", "path", package_name, timeout=30)
    remote_paths = parse_pm_path_output(result.stdout) if result.returncode == 0 else []
    if not remote_paths:
        return None

    remote_apk = next((item for item in remote_paths if item.endswith("/base.apk")), remote_paths[0])
    dest_dir.mkdir(parents=True, exist_ok=True)
    dest_apk = dest_dir / "base.apk"
    pulled = adb(ctx.args, "pull", remote_apk, str(dest_apk), timeout=120)
    if pulled.returncode != 0:
        return None
    return dest_apk


def parse_pm_path_output(output: str) -> List[str]:
    remote_paths: List[str] = []
    for line in output.splitlines():
        line = line.strip()
        if line.startswith("package:"):
            remote_paths.append(line.removeprefix("package:").strip())
    return remote_paths


def package_installed(ctx: Context, package_name: str) -> Tuple[bool, CommandRecord]:
    result = adb(ctx.args, "shell", "pm", "path", package_name, timeout=30)
    return bool(parse_pm_path_output(result.stdout)) and result.returncode == 0, result


def extract_apk(apk_path: Path, dest_dir: Path) -> bool:
    dest_dir.mkdir(parents=True, exist_ok=True)
    try:
        with zipfile.ZipFile(apk_path) as archive:
            archive.extractall(dest_dir)
        return True
    except zipfile.BadZipFile:
        return False


def abi_from_path(path: Path) -> Optional[str]:
    parts = list(path.parts)
    for index, part in enumerate(parts):
        if part == "lib" and index + 1 < len(parts):
            return parts[index + 1]
    return None


def find_native_libraries(extract_dir: Path) -> List[NativeLibrary]:
    libraries: List[NativeLibrary] = []
    for so_path in sorted(extract_dir.rglob("*.so")):
        libraries.append(
            NativeLibrary(
                path=str(so_path),
                name=so_path.name,
                abi=abi_from_path(so_path),
                size=so_path.stat().st_size,
            )
        )
    return libraries


def preferred_libraries(libraries: List[NativeLibrary], device_abi: Optional[str]) -> List[NativeLibrary]:
    if not device_abi:
        return libraries
    matching = [library for library in libraries if library.abi == device_abi]
    return matching or libraries


def symbol_score(symbol: str) -> int:
    lower = symbol.lower()
    score = 0
    for keyword, weight in KEYWORD_WEIGHTS:
        if keyword in lower:
            score += weight
    return score


def parse_readelf_symbols(output: str) -> Iterable[str]:
    for line in output.splitlines():
        parts = line.split()
        if len(parts) < 8:
            continue
        if parts[3] != "FUNC":
            continue
        if parts[6] == "UND":
            continue
        name = parts[-1].split("@", 1)[0]
        if name and name != "0":
            yield name


def parse_nm_symbols(output: str) -> Iterable[str]:
    for line in output.splitlines():
        parts = line.split()
        if len(parts) < 2:
            continue
        name = parts[-1].split("@", 1)[0]
        if name:
            yield name


def discover_symbols(libraries: List[NativeLibrary], max_symbols_per_lib: int) -> List[CandidateSymbol]:
    readelf = shutil.which("readelf")
    nm = shutil.which("nm")
    candidates: List[CandidateSymbol] = []

    for library in libraries:
        path = Path(library.path)
        symbols: List[Tuple[str, str]] = []
        if readelf:
            result = run_command([readelf, "-Ws", str(path)], timeout=30)
            if result.returncode == 0:
                symbols.extend((symbol, "readelf") for symbol in parse_readelf_symbols(result.stdout))

        if not symbols and nm:
            result = run_command([nm, "-D", "--defined-only", str(path)], timeout=30)
            if result.returncode == 0:
                symbols.extend((symbol, "nm") for symbol in parse_nm_symbols(result.stdout))

        seen = set()
        kept = 0
        for symbol, source in symbols:
            if symbol in seen:
                continue
            seen.add(symbol)
            score = symbol_score(symbol)
            if score <= 0:
                continue
            candidates.append(
                CandidateSymbol(
                    library_path=library.path,
                    library_name=library.name,
                    symbol=symbol,
                    score=score,
                    source=source,
                )
            )
            kept += 1
            if kept >= max_symbols_per_lib:
                break

    candidates.sort(key=lambda item: (item.score, item.symbol.startswith("Java_")), reverse=True)
    return candidates


def summarize_event_log(path: Path) -> Dict[str, Any]:
    summary: Dict[str, Any] = {
        "exists": path.exists(),
        "api_event_count": 0,
        "state_packet_count": 0,
        "solver_solution_count": 0,
        "kinds": {},
    }
    if not path.exists():
        return summary

    with path.open("r", encoding="utf-8", errors="replace") as handle:
        for line in handle:
            try:
                record = json.loads(line)
            except json.JSONDecodeError:
                continue
            if record.get("type") == "API_EVENT":
                summary["api_event_count"] += 1
                kind = str(record.get("kind") or "unknown")
                summary["kinds"][kind] = summary["kinds"].get(kind, 0) + 1
            if record.get("type") == "state_packet":
                summary["state_packet_count"] += 1
            if record.get("type") == "solver_solution":
                summary["solver_solution_count"] += 1

    return summary


def orchestrator_base_args(ctx: Context, package_name: str, event_log: Path, duration: int) -> List[str]:
    args = [
        ctx.python_bin,
        str(ORCHESTRATOR),
        "--package",
        package_name,
        "--remote",
        ctx.args.frida_remote,
        "--duration",
        str(duration),
        "--event-log",
        str(event_log),
    ]
    return args


def run_runtime_trace(ctx: Context, package_name: str, app_dir: Path) -> Dict[str, Any]:
    if ctx.args.skip_runtime:
        return {"skipped": True}

    event_log = app_dir / "runtime-events.jsonl"
    stdout_log = app_dir / "runtime-stdout.log"
    command = orchestrator_base_args(ctx, package_name, event_log, ctx.args.duration)
    command.extend(["--disable-solving", "--disable-concolic-gate"])

    print(f"[*] Capturing API/crypto runtime telemetry for {package_name}...")
    result = run_command(
        command,
        cwd=REPO_ROOT,
        timeout=ctx.args.duration + 90,
        stdout_path=stdout_log,
    )

    return {
        "command": shell_quote_command(command),
        "result": asdict(result),
        "event_log": str(event_log),
        "stdout_log": str(stdout_log),
        "summary": summarize_event_log(event_log),
    }


def run_native_probes(
    ctx: Context,
    package_name: str,
    candidates: List[CandidateSymbol],
    app_dir: Path,
) -> List[Dict[str, Any]]:
    if ctx.args.skip_runtime or ctx.args.native_probe_limit <= 0:
        return []

    probes: List[Dict[str, Any]] = []
    selected = candidates[: ctx.args.native_probe_limit]
    for index, candidate in enumerate(selected, start=1):
        event_log = app_dir / f"native-probe-{index}-{sanitize_name(candidate.symbol)}.jsonl"
        stdout_log = app_dir / f"native-probe-{index}-{sanitize_name(candidate.symbol)}.log"
        command = orchestrator_base_args(ctx, package_name, event_log, ctx.args.native_probe_duration)
        command.extend([
            "--binary",
            candidate.library_path,
            "--target-so",
            candidate.library_name,
            "--target-symbol",
            candidate.symbol,
            "--input-arg-index",
            str(ctx.args.input_arg_index),
            "--length",
            str(ctx.args.length),
        ])

        solving_enabled = ctx.args.enable_solving and (ctx.args.success_offset or ctx.args.success_address)
        if ctx.args.success_offset:
            command.extend(["--success-offset", ctx.args.success_offset])
        if ctx.args.failure_offset:
            command.extend(["--failure-offset", ctx.args.failure_offset])
        if ctx.args.success_address:
            command.extend(["--success-address", ctx.args.success_address])
        if ctx.args.failure_address:
            command.extend(["--failure-address", ctx.args.failure_address])
        if not solving_enabled:
            command.append("--disable-solving")

        print(f"[*] Probing native candidate {candidate.library_name}!{candidate.symbol}...")
        result = run_command(
            command,
            cwd=REPO_ROOT,
            timeout=ctx.args.native_probe_duration + 90,
            stdout_path=stdout_log,
        )

        probes.append({
            "candidate": asdict(candidate),
            "solving_enabled": solving_enabled,
            "command": shell_quote_command(command),
            "result": asdict(result),
            "event_log": str(event_log),
            "stdout_log": str(stdout_log),
            "summary": summarize_event_log(event_log),
        })

    return probes


def device_abi(args: argparse.Namespace) -> Optional[str]:
    result = adb(args, "shell", "getprop", "ro.product.cpu.abi", timeout=20)
    if result.returncode != 0:
        return None
    return result.stdout.strip().replace("\r", "") or None


def analyze_target(ctx: Context, target: Target, index: int) -> Dict[str, Any]:
    app_started = utc_now()
    report: Dict[str, Any] = {
        "target": asdict(target),
        "started_at": app_started,
        "errors": [],
    }

    package_name: Optional[str] = None
    apk_path: Optional[Path] = None
    before_packages: set[str] = set()

    if target.kind == "apk":
        apk_path = Path(target.value)
        package_name = extract_package_from_apk(apk_path)
        report["apk_package_from_manifest"] = package_name
        if not package_name and not ctx.args.skip_install:
            before_packages = package_list(ctx.args)
        installed_package, install_report = install_apk(ctx, apk_path, before_packages)
        report["install"] = install_report
        package_name = package_name or installed_package
    elif target.kind == "package":
        package_name = target.value
        installed, lookup = package_installed(ctx, package_name)
        report["package_lookup"] = asdict(lookup)
        if not installed:
            raise PipelineError(f"Package is not installed on the device: {package_name}")
        report["install"] = {"skipped": True, "reason": "package target"}
    else:
        raise PipelineError(f"Unsupported target kind: {target.kind}")

    if not package_name:
        raise PipelineError(f"Could not resolve package name for target: {target.value}")

    report["package"] = package_name
    app_dir = ctx.output_dir / f"{index:03d}-{sanitize_name(package_name)}"
    app_dir.mkdir(parents=True, exist_ok=True)

    if apk_path is None:
        pulled = pull_package_apk(ctx, package_name, app_dir / "pulled-apk")
        if pulled:
            apk_path = pulled
            report["pulled_apk"] = str(pulled)
        else:
            report["errors"].append("Could not pull package APK from device; native extraction skipped.")

    if apk_path:
        report["apk_path"] = str(apk_path)
        extract_dir = app_dir / "apk"
        if extract_apk(apk_path, extract_dir):
            report["extract_dir"] = str(extract_dir)
            abi = device_abi(ctx.args)
            report["device_abi"] = abi
            libraries = find_native_libraries(extract_dir)
            selected_libraries = preferred_libraries(libraries, abi)
            candidates = discover_symbols(selected_libraries, ctx.args.max_symbols_per_lib)
            report["native_libraries"] = [asdict(item) for item in libraries]
            report["selected_native_libraries"] = [asdict(item) for item in selected_libraries]
            report["candidate_symbols"] = [asdict(item) for item in candidates]
        else:
            report["errors"].append("APK extraction failed; native discovery skipped.")
            candidates = []
    else:
        candidates = []

    report["runtime_trace"] = run_runtime_trace(ctx, package_name, app_dir)
    report["native_probes"] = run_native_probes(ctx, package_name, candidates, app_dir)
    report["finished_at"] = utc_now()
    return report


def write_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def write_markdown_summary(path: Path, report: Dict[str, Any]) -> None:
    lines = [
        "# Mobile Security Engine Automation Report",
        "",
        f"- Started: `{report.get('started_at')}`",
        f"- Finished: `{report.get('finished_at')}`",
        f"- Output directory: `{report.get('output_dir')}`",
        f"- Targets: `{len(report.get('targets', []))}`",
        "",
        "## Applications",
        "",
    ]

    for app in report.get("applications", []):
        package_name = app.get("package", "unknown")
        errors = app.get("errors") or []
        runtime = app.get("runtime_trace") or {}
        runtime_summary = runtime.get("summary") or {}
        candidates = app.get("candidate_symbols") or []
        probes = app.get("native_probes") or []
        libraries = app.get("native_libraries") or []

        lines.extend([
            f"### {package_name}",
            "",
            f"- Target: `{app.get('target', {}).get('value')}`",
            f"- Runtime event log: `{runtime.get('event_log', 'n/a')}`",
            f"- API events: `{runtime_summary.get('api_event_count', 0)}`",
            f"- Native libraries: `{len(libraries)}`",
            f"- Candidate symbols: `{len(candidates)}`",
            f"- Native probes: `{len(probes)}`",
        ])

        if errors:
            lines.append(f"- Errors: `{'; '.join(errors)}`")

        top_candidates = candidates[:5]
        if top_candidates:
            lines.append("")
            lines.append("Top native candidates:")
            for candidate in top_candidates:
                lines.append(
                    f"- `{candidate['library_name']}!{candidate['symbol']}` score `{candidate['score']}`"
                )

        lines.append("")

    failures = report.get("failures") or []
    if failures:
        lines.extend([
            "## Failures",
            "",
        ])
        for failure in failures:
            target = failure.get("target", {})
            lines.append(f"- `{target.get('value', 'unknown')}`: {failure.get('error', 'unknown error')}")
        lines.append("")

    path.write_text("\n".join(lines), encoding="utf-8")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Provision Android runtime analysis and automatically analyze APKs or installed packages."
    )
    parser.add_argument("targets", nargs="*", help="APK file, APK directory, package name, or a text file containing targets.")
    parser.add_argument("--apk", action="append", help="APK file to install and analyze. May be repeated.")
    parser.add_argument("--apk-dir", action="append", help="Directory of APK files to analyze recursively. May be repeated.")
    parser.add_argument("--package", dest="packages", action="append", help="Already installed Android package to analyze. May be repeated.")
    parser.add_argument("--target-list", help="Text file containing APK paths, APK directories, or package names.")
    parser.add_argument("--installed-user-apps", action="store_true", help="Analyze all third-party packages currently installed on the device.")
    parser.add_argument("--output-dir", help="Directory for reports and artifacts. Defaults to /tmp/mobile-security-engine-runs/<timestamp>.")
    parser.add_argument("--duration", type=int, default=60, help="Runtime API/crypto trace duration per app.")
    parser.add_argument("--native-probe-duration", type=int, default=20, help="Duration per native candidate probe.")
    parser.add_argument("--native-probe-limit", type=int, default=3, help="Maximum native candidate symbols to probe per app. Use 0 to disable.")
    parser.add_argument("--max-symbols-per-lib", type=int, default=200, help="Maximum scored native symbols retained per library.")
    parser.add_argument("--frida-remote", default=os.environ.get("FRIDA_REMOTE", "127.0.0.1:27042"), help="Remote Frida host:port.")
    parser.add_argument("--adb", default=os.environ.get("ADB", "adb"), help="ADB executable.")
    parser.add_argument("--adb-serial", default=os.environ.get("ADB_SERIAL"), help="ADB serial/device ID.")
    parser.add_argument("--skip-provision", action="store_true", help="Skip emulator/proxy provisioning.")
    parser.add_argument("--skip-frida", action="store_true", help="Skip frida-server setup.")
    parser.add_argument("--skip-install", action="store_true", help="Do not install APK targets before analysis.")
    parser.add_argument("--skip-runtime", action="store_true", help="Skip Frida runtime tracing and only extract native metadata.")
    parser.add_argument("--enable-solving", action="store_true", help="Enable angr solving for native probes when success target data is supplied.")
    parser.add_argument("--success-offset", help="Success offset from probed target symbol.")
    parser.add_argument("--failure-offset", help="Failure offset from probed target symbol.")
    parser.add_argument("--success-address", help="Absolute success address.")
    parser.add_argument("--failure-address", help="Absolute failure address.")
    parser.add_argument("--input-arg-index", type=int, default=2, help="Native argument index containing the target input pointer.")
    parser.add_argument("--length", type=int, default=32, help="Symbolic input length for native probes.")
    parser.add_argument("--strict", action="store_true", help="Exit non-zero if any target fails.")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    timestamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    output_dir = Path(args.output_dir).expanduser().resolve() if args.output_dir else DEFAULT_RUN_ROOT / timestamp
    output_dir.mkdir(parents=True, exist_ok=True)

    ctx = Context(args=args, output_dir=output_dir, python_bin=choose_python())
    report: Dict[str, Any] = {
        "started_at": utc_now(),
        "output_dir": str(output_dir),
        "python": ctx.python_bin,
        "arguments": vars(args),
        "targets": [],
        "applications": [],
        "failures": [],
    }

    try:
        initial_targets = resolve_initial_targets(args)
        if not initial_targets and not args.installed_user_apps:
            raise PipelineError("No targets provided. Pass an APK path, APK directory, package name, --target-list, or --installed-user-apps.")

        report["targets"] = [asdict(target) for target in initial_targets]
        write_json(output_dir / "report.json", report)

        provision_environment(ctx, report)

        if args.installed_user_apps:
            initial_targets.extend(installed_user_packages(args))

        deduped: List[Target] = []
        seen = set()
        for target in initial_targets:
            key = (target.kind, target.value)
            if key in seen:
                continue
            seen.add(key)
            deduped.append(target)

        if not deduped:
            raise PipelineError("No analyzable targets were found.")

        report["targets"] = [asdict(target) for target in deduped]
        write_json(output_dir / "report.json", report)

        for index, target in enumerate(deduped, start=1):
            print(f"[*] Analyzing target {index}/{len(deduped)}: {target.value}")
            try:
                app_report = analyze_target(ctx, target, index)
                report["applications"].append(app_report)
            except Exception as exc:
                failure = {
                    "target": asdict(target),
                    "error": str(exc),
                    "failed_at": utc_now(),
                }
                report["failures"].append(failure)
                print(f"[-] Target failed: {target.value}: {exc}")
                if args.strict:
                    raise
            finally:
                write_json(output_dir / "report.json", report)
                write_markdown_summary(output_dir / "summary.md", report)

        report["finished_at"] = utc_now()
        write_json(output_dir / "report.json", report)
        write_markdown_summary(output_dir / "summary.md", report)
        print(f"[+] Automation complete. Report: {output_dir / 'summary.md'}")
        print(f"[+] Machine-readable report: {output_dir / 'report.json'}")
        return 1 if args.strict and report["failures"] else 0
    except Exception as exc:
        report["fatal_error"] = str(exc)
        report["finished_at"] = utc_now()
        write_json(output_dir / "report.json", report)
        write_markdown_summary(output_dir / "summary.md", report)
        print(f"[-] Automation failed: {exc}", file=sys.stderr)
        print(f"[*] Partial report: {output_dir / 'report.json'}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
