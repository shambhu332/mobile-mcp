#!/usr/bin/env python3
# concolic_engine/orchestrator.py

from __future__ import annotations

import argparse
import json
import os
import sys
import time
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional

angr = None

try:
    import frida
except ModuleNotFoundError:
    frida = None


REPO_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_AGENT = REPO_ROOT / "concolic_engine" / "agent.js"
DEFAULT_EVENT_LOG = Path("/tmp/mobile-security-engine-runtime-events.jsonl")


@dataclass
class SolverConfig:
    package_name: str
    binary_path: Optional[Path]
    target_so: str
    target_symbol: str
    success_offset: Optional[int]
    failure_offset: Optional[int]
    success_address: Optional[int]
    failure_address: Optional[int]
    input_arg_index: int
    symbolic_length: int
    solve_timeout: int
    max_steps: int
    max_active: int
    max_per_address: int
    loop_bound: int
    enable_veritesting: bool
    enable_unicorn: bool
    disable_solving: bool


class RuntimeRecorder:
    def __init__(self, output_path: Path):
        self.output_path = output_path
        self.output_path.parent.mkdir(parents=True, exist_ok=True)

    def write(self, record: Dict[str, Any]) -> None:
        record.setdefault("host_time", time.time())
        with self.output_path.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(record, sort_keys=True) + "\n")


def parse_int(value: Optional[str]) -> Optional[int]:
    if value is None or value == "":
        return None
    return int(value, 0)


def load_angr() -> bool:
    global angr
    if angr is not None:
        return True

    try:
        import angr as angr_module
    except ModuleNotFoundError:
        return False

    angr = angr_module
    return True


def bytes_from_page(page: Dict[str, Any]) -> bytes:
    data = page.get("data", [])
    return bytes((int(byte) & 0xFF) for byte in data)


def page_permissions(protection: str) -> int:
    permissions = 0
    if "r" in protection:
        permissions |= 1
    if "w" in protection:
        permissions |= 2
    if "x" in protection:
        permissions |= 4
    return permissions


def register_aliases(architecture: str) -> Dict[str, str]:
    if architecture == "arm64":
        return {
            "fp": "x29",
            "lr": "x30",
            "sp": "sp",
            "pc": "pc",
        }

    if architecture == "arm":
        return {
            "sp": "sp",
            "lr": "lr",
            "pc": "pc",
        }

    if architecture == "x64":
        return {
            "pc": "rip",
            "rip": "rip",
            "sp": "rsp",
            "rsp": "rsp",
            "bp": "rbp",
            "rbp": "rbp",
        }

    if architecture == "ia32":
        return {
            "pc": "eip",
            "eip": "eip",
            "sp": "esp",
            "esp": "esp",
            "bp": "ebp",
            "ebp": "ebp",
        }

    return {"pc": "pc"}


def configure_state_options(state: angr.SimState, config: SolverConfig) -> None:
    if angr is None:
        return

    state.options.add(angr.options.LAZY_SOLVES)
    state.options.add(angr.options.ZERO_FILL_UNCONSTRAINED_MEMORY)
    state.options.add(angr.options.ZERO_FILL_UNCONSTRAINED_REGISTERS)

    if config.enable_unicorn:
        try:
            state.options.add(angr.options.UNICORN)
        except Exception:
            pass


def map_runtime_pages(state: angr.SimState, pages: Iterable[Dict[str, Any]]) -> int:
    mapped = 0
    for page in pages:
        base_addr = int(page["base"], 16)
        raw_data = bytes_from_page(page)
        size = int(page.get("size") or len(raw_data))
        protection = str(page.get("protection", "rw-"))
        permissions = page_permissions(protection)

        try:
            state.memory.map_region(addr=base_addr, length=size, permissions=permissions)
        except Exception:
            pass

        state.memory.store(base_addr, raw_data)
        mapped += 1

    return mapped


def sync_registers(state: angr.SimState, architecture: str, registers: Dict[str, str]) -> None:
    aliases = register_aliases(architecture)
    for reg, hex_val in registers.items():
        angr_reg = aliases.get(reg, reg)
        try:
            setattr(state.regs, angr_reg, int(hex_val, 16))
        except Exception:
            continue


def install_lazy_memory_fallback(state: angr.SimState) -> None:
    def memory_read_fallback(inner_state: angr.SimState) -> None:
        try:
            invalid_addr = inner_state.inspect.mem_read_address
            read_size = inner_state.inspect.mem_read_length
            concrete_addr = inner_state.solver.eval(invalid_addr)
            concrete_size = inner_state.solver.eval(read_size) if not isinstance(read_size, int) else read_size
            if concrete_addr <= 0 or concrete_size <= 0:
                return

            page_base = concrete_addr & ~0xFFF
            page_size = max(0x1000, ((concrete_size + 0xFFF) // 0x1000) * 0x1000)
            try:
                inner_state.memory.map_region(addr=page_base, length=page_size, permissions=3)
            except Exception:
                pass

            fallback = inner_state.solver.BVS(f"fallback_mem_{page_base:x}", page_size * 8)
            inner_state.memory.store(page_base, fallback)
        except Exception:
            return

    state.inspect.b("mem_read", when=angr.BP_BEFORE, action=memory_read_fallback)


def resolve_target_addresses(project: angr.Project, config: SolverConfig) -> tuple[Optional[int], Optional[int]]:
    if config.success_address is not None:
        success = config.success_address
    else:
        success = None

    if config.failure_address is not None:
        failure = config.failure_address
    else:
        failure = None

    symbol = project.loader.find_symbol(config.target_symbol)
    if symbol is not None:
        entry = symbol.rebased_addr
        if success is None and config.success_offset is not None:
            success = entry + config.success_offset
        if failure is None and config.failure_offset is not None:
            failure = entry + config.failure_offset

    return success, failure


def state_is_at(address: Optional[int]):
    if address is None:
        return lambda _state: False
    return lambda state: state.addr == address


def limit_active_states(simgr: angr.SimulationManager, config: SolverConfig) -> None:
    active = list(simgr.stashes.get("active", []))
    if not active:
        return

    by_address: Dict[int, List[angr.SimState]] = {}
    for state in active:
        by_address.setdefault(state.addr, []).append(state)

    kept: List[angr.SimState] = []
    pruned: List[angr.SimState] = []
    for states in by_address.values():
        kept.extend(states[: config.max_per_address])
        pruned.extend(states[config.max_per_address :])

    if len(kept) > config.max_active:
        pruned.extend(kept[config.max_active :])
        kept = kept[: config.max_active]

    simgr.stashes["active"] = kept
    simgr.stashes.setdefault("pruned", []).extend(pruned)


def apply_exploration_techniques(simgr: angr.SimulationManager, config: SolverConfig) -> None:
    if angr is None:
        return

    try:
        simgr.use_technique(angr.exploration_techniques.LoopSeer(bound=config.loop_bound))
    except Exception:
        pass

    if config.enable_veritesting:
        try:
            simgr.use_technique(angr.exploration_techniques.Veritesting())
        except Exception:
            pass


def solve_with_limits(
    project: angr.Project,
    state: angr.SimState,
    success_address: int,
    failure_address: Optional[int],
    config: SolverConfig,
) -> tuple[Optional[angr.SimState], Dict[str, Any]]:
    simgr = project.factory.simgr(state)
    apply_exploration_techniques(simgr, config)

    started = time.monotonic()
    steps = 0
    stats: Dict[str, Any] = {
        "success_address": hex(success_address),
        "failure_address": hex(failure_address) if failure_address is not None else None,
        "timed_out": False,
        "max_steps_reached": False,
        "steps": 0,
        "found": False,
    }

    while simgr.active and not simgr.found:
        if time.monotonic() - started > config.solve_timeout:
            stats["timed_out"] = True
            break

        if steps >= config.max_steps:
            stats["max_steps_reached"] = True
            break

        simgr.move(from_stash="active", to_stash="found", filter_func=state_is_at(success_address))
        if failure_address is not None:
            simgr.move(from_stash="active", to_stash="avoid", filter_func=state_is_at(failure_address))

        if simgr.found:
            break

        simgr.step()
        steps += 1
        limit_active_states(simgr, config)

    stats["steps"] = steps
    stats["found"] = bool(simgr.found)
    stats["active"] = len(simgr.stashes.get("active", []))
    stats["avoid"] = len(simgr.stashes.get("avoid", []))
    stats["deadended"] = len(simgr.stashes.get("deadended", []))
    stats["pruned"] = len(simgr.stashes.get("pruned", []))

    if simgr.found:
        return simgr.found[0], stats

    return None, stats


def fallback_solution(length: int) -> List[int]:
    return list(b"\x00" * max(0, length))


def handle_symbolic_solving(snapshot_data: Dict[str, Any], config: SolverConfig, recorder: RuntimeRecorder) -> List[int]:
    length = int(snapshot_data.get("length", config.symbolic_length))
    if config.disable_solving:
        recorder.write({
            "type": "solver_skipped",
            "reason": "disabled",
            "snapshot": {
                "architecture": snapshot_data.get("architecture"),
                "target_function": snapshot_data.get("target_function"),
                "pages": len(snapshot_data.get("pages", [])),
            },
        })
        return fallback_solution(length)

    if not load_angr():
        recorder.write({
            "type": "solver_skipped",
            "reason": "missing_angr",
            "hint": "Install angr or run with --disable-solving for API and crypto telemetry only.",
        })
        return fallback_solution(length)

    if not config.binary_path or not config.binary_path.exists():
        recorder.write({
            "type": "solver_skipped",
            "reason": "missing_binary",
            "binary_path": str(config.binary_path) if config.binary_path else None,
        })
        return fallback_solution(length)

    try:
        project = angr.Project(str(config.binary_path), auto_load_libs=False)
        registers = snapshot_data["registers"]
        pc_val = int(registers["pc"], 16)
        state = project.factory.blank_state(addr=pc_val)
        configure_state_options(state, config)
        mapped_pages = map_runtime_pages(state, snapshot_data.get("pages", []))
        sync_registers(state, str(snapshot_data.get("architecture", "")), registers)
        install_lazy_memory_fallback(state)

        success_address, failure_address = resolve_target_addresses(project, config)
        if success_address is None:
            recorder.write({
                "type": "solver_skipped",
                "reason": "missing_success_target",
                "target_symbol": config.target_symbol,
            })
            return fallback_solution(length)

        solved_state, stats = solve_with_limits(project, state, success_address, failure_address, config)
        stats["mapped_pages"] = mapped_pages
        recorder.write({"type": "solver_stats", **stats})

        if solved_state is None:
            return fallback_solution(length)

        target_buf_ptr = int(snapshot_data["target_ptr"], 16)
        resolved_bytes = solved_state.solver.eval(
            solved_state.memory.load(target_buf_ptr, length),
            cast_to=bytes,
        )
        recorder.write({
            "type": "solver_solution",
            "target_ptr": snapshot_data["target_ptr"],
            "length": len(resolved_bytes),
            "solution_hex": resolved_bytes.hex(),
        })
        return list(resolved_bytes)
    except Exception as exc:
        recorder.write({
            "type": "solver_error",
            "error": str(exc),
            "snapshot": {
                "architecture": snapshot_data.get("architecture"),
                "target_function": snapshot_data.get("target_function"),
                "pages": len(snapshot_data.get("pages", [])),
            },
        })
        return fallback_solution(length)


def build_agent_config(args: argparse.Namespace) -> Dict[str, Any]:
    return {
        "targetSo": args.target_so,
        "targetFunction": args.target_symbol,
        "inputArgIndex": args.input_arg_index,
        "symbolicLength": args.length,
        "maxPages": args.max_pages,
        "maxPageBytes": args.max_page_bytes,
        "enableApiHooks": not args.disable_api_hooks,
        "enableCryptoHooks": not args.disable_crypto_hooks,
        "enableNativeHooks": not args.disable_native_hooks,
        "enableAntiAnalysisBypass": not args.disable_anti_analysis_bypass,
        "enableConcolicGate": not args.disable_concolic_gate,
    }


def load_agent_source(agent_path: Path, agent_config: Dict[str, Any]) -> str:
    source = agent_path.read_text(encoding="utf-8")
    encoded_config = json.dumps(agent_config)
    return source.replace('"__MSE_AGENT_CONFIG_JSON__"', encoded_config)


def choose_device(args: argparse.Namespace):
    if frida is None:
        sys.exit("[-] Missing Python dependency: frida. Install frida-tools before running device instrumentation.")

    if args.remote:
        return frida.get_device_manager().add_remote_device(args.remote)

    if args.device_id:
        return frida.get_device(args.device_id, timeout=args.device_timeout)
    return frida.get_usb_device(timeout=args.device_timeout)


def create_solver_config(args: argparse.Namespace) -> SolverConfig:
    binary_path = Path(args.binary).resolve() if args.binary else None
    return SolverConfig(
        package_name=args.package,
        binary_path=binary_path,
        target_so=args.target_so,
        target_symbol=args.target_symbol,
        success_offset=parse_int(args.success_offset),
        failure_offset=parse_int(args.failure_offset),
        success_address=parse_int(args.success_address),
        failure_address=parse_int(args.failure_address),
        input_arg_index=args.input_arg_index,
        symbolic_length=args.length,
        solve_timeout=args.solve_timeout,
        max_steps=args.max_steps,
        max_active=args.max_active,
        max_per_address=args.max_per_address,
        loop_bound=args.loop_bound,
        enable_veritesting=args.enable_veritesting,
        enable_unicorn=args.enable_unicorn,
        disable_solving=args.disable_solving,
    )


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Runtime API visibility and concolic solving orchestrator.")
    parser.add_argument("--package", required=True, help="Android package name to spawn and instrument.")
    parser.add_argument("--binary", help="Local native library path for angr, if concolic solving is enabled.")
    parser.add_argument("--target-so", default="libnative-lib.so", help="Loaded native library name to instrument.")
    parser.add_argument("--target-symbol", default="Java_com_example_app_NativeBridge_verifySecureToken", help="Exported native symbol to intercept.")
    parser.add_argument("--success-offset", default="0x14C2", help="Offset from target symbol that represents success.")
    parser.add_argument("--failure-offset", default="0x14F0", help="Offset from target symbol that represents failure.")
    parser.add_argument("--success-address", help="Absolute success address. Overrides --success-offset.")
    parser.add_argument("--failure-address", help="Absolute failure address. Overrides --failure-offset.")
    parser.add_argument("--input-arg-index", type=int, default=2, help="Native function argument index containing the symbolic input pointer.")
    parser.add_argument("--length", type=int, default=32, help="Symbolic input length in bytes.")
    parser.add_argument("--event-log", default=str(DEFAULT_EVENT_LOG), help="JSONL output path for runtime API and solver telemetry.")
    parser.add_argument("--agent", default=str(DEFAULT_AGENT), help="Frida JavaScript agent path.")
    parser.add_argument("--device-id", help="Explicit Frida device ID. Defaults to first USB device.")
    parser.add_argument("--remote", default=os.environ.get("FRIDA_REMOTE"), help="Remote Frida host:port, e.g. 127.0.0.1:27042 for ADB-forwarded Genymotion.")
    parser.add_argument("--device-timeout", type=int, default=10, help="Seconds to wait for the Frida device.")
    parser.add_argument("--duration", type=int, default=0, help="Run for N seconds then detach. Default 0 waits for stdin EOF.")
    parser.add_argument("--solve-timeout", type=int, default=60, help="Maximum seconds per symbolic solve.")
    parser.add_argument("--max-steps", type=int, default=1000, help="Maximum angr steps per solve.")
    parser.add_argument("--max-active", type=int, default=64, help="Maximum active states retained per step.")
    parser.add_argument("--max-per-address", type=int, default=4, help="Maximum active states retained per address.")
    parser.add_argument("--loop-bound", type=int, default=3, help="LoopSeer iteration bound.")
    parser.add_argument("--max-pages", type=int, default=48, help="Maximum runtime memory pages sent by the Frida agent.")
    parser.add_argument("--max-page-bytes", type=int, default=65536, help="Maximum bytes carved from a single runtime memory page.")
    parser.add_argument("--enable-veritesting", action="store_true", help="Enable angr Veritesting exploration technique.")
    parser.add_argument("--enable-unicorn", action="store_true", help="Enable angr Unicorn acceleration when available.")
    parser.add_argument("--disable-solving", action="store_true", help="Collect API telemetry without invoking angr.")
    parser.add_argument("--disable-api-hooks", action="store_true", help="Disable Java network/WebView API hooks.")
    parser.add_argument("--disable-crypto-hooks", action="store_true", help="Disable Java cryptographic hooks.")
    parser.add_argument("--disable-native-hooks", action="store_true", help="Disable native SSL/libcrypto hooks.")
    parser.add_argument("--disable-anti-analysis-bypass", action="store_true", help="Disable ptrace/TracerPid bypass hooks.")
    parser.add_argument("--disable-concolic-gate", action="store_true", help="Disable native gate interception.")
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    recorder = RuntimeRecorder(Path(args.event_log).resolve())
    solver_config = create_solver_config(args)
    agent_config = build_agent_config(args)

    recorder.write({
        "type": "orchestrator_start",
        "solver_config": {
            **asdict(solver_config),
            "binary_path": str(solver_config.binary_path) if solver_config.binary_path else None,
        },
        "agent_config": agent_config,
    })

    device = choose_device(args)
    pid = device.spawn([args.package])
    session = device.attach(pid)
    script = session.create_script(load_agent_source(Path(args.agent), agent_config))

    def on_message(message: Dict[str, Any], data: Any) -> None:
        if message.get("type") == "send":
            payload = message.get("payload", {})
            payload_type = payload.get("type")

            if payload_type == "STATE_PACKET":
                recorder.write({
                    "type": "state_packet",
                    "architecture": payload.get("architecture"),
                    "target_function": payload.get("target_function"),
                    "target_ptr": payload.get("target_ptr"),
                    "pages": len(payload.get("pages", [])),
                    "register_count": len(payload.get("registers", {})),
                })
                solved_bytes = handle_symbolic_solving(payload, solver_config, recorder)
                script.post({
                    "type": "SOLVE_REPLY",
                    "payload": solved_bytes,
                    "target_ptr": payload["target_ptr"],
                })
                return

            if payload_type == "API_EVENT":
                recorder.write(payload)
                print(json.dumps(payload, sort_keys=True))
                return

            recorder.write({"type": "frida_send", "payload": payload})
            print(json.dumps(payload, sort_keys=True))
            return

        recorder.write({"type": "frida_message", "message": message})
        print(message)

    script.on("message", on_message)
    script.load()
    device.resume(pid)

    print(f"[*] Instrumenting {args.package}. Runtime events: {recorder.output_path}")
    try:
        if args.duration > 0:
            time.sleep(args.duration)
        else:
            sys.stdin.read()
    finally:
        recorder.write({"type": "orchestrator_stop"})
        try:
            session.detach()
        except Exception:
            pass


if __name__ == "__main__":
    main()
