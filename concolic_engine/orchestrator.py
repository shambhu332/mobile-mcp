# concolic_engine/orchestrator.py

import frida
import angr
import sys
import os

TARGET_SO_PATH = "./app/src/main/jni/libnative-lib.so"
PACKAGE_NAME = "com.example.app"

def handle_symbolic_solving(snapshot_data):
    """
    Spins up an angr project, restores registers/dynamic memory pages,
    safely handles page-fault errors, and solves paths.
    """
    print("\n[*] Initializing angr symbolic project context...")
    project = angr.Project(TARGET_SO_PATH, auto_load_libs=False)

    regs = snapshot_data["registers"]
    pc_val = int(regs["pc"], 16)
    
    # 1. Instantiate the SimState checkpoint
    state = project.factory.blank_state(addr=pc_val)

    # 2. Map dynamically carved stack and heap pages
    print("[*] Reconstituting Dynamic Heap and Stack Segments...")
    for page in snapshot_data["pages"]:
        base_addr = int(page["base"], 16)
        size = page["size"]
        raw_data = bytes(page["data"])
        protection = page["protection"]

        permissions = 0
        if 'r' in protection: permissions |= 1
        if 'w' in protection: permissions |= 2
        if 'x' in protection: permissions |= 4

        state.memory.map_region(addr=base_addr, length=size, permissions=permissions)
        state.memory.store(base_addr, raw_data)

    # 3. Synchronize execution registers
    register_map = {"fp": "x29", "lr": "x30"}
    for reg, hex_val in regs.items():
        val = int(hex_val, 16)
        angr_reg = register_map.get(reg, reg)
        try:
            setattr(state.regs, angr_reg, val)
        except AttributeError:
            pass

    # 4. Lazy Memory-Mapping for un-carved memory accesses
    def memory_read_fallback(state):
        invalid_addr = state.inspect.mem_read_address
        read_size = state.inspect.mem_read_length
        print(f"[!] Dynamic Fallback: Mapping un-carved address {invalid_addr} ({read_size} bytes)")
        symbolic_var = state.solver.BVS("fallback_mem", read_size * 8)
        state.memory.store(invalid_addr, symbolic_var)

    state.inspect.b('mem_read', when=angr.BP_BEFORE, action=memory_read_fallback)

    # 5. Define target and execution offsets (obtained via static disassembly)
    target_symbol = project.loader.find_symbol("Java_com_example_app_NativeBridge_verifySecureToken")
    entry_addr = target_symbol.rebased_addr
    
    success_address = entry_addr + 0x14C2
    failure_address = entry_addr + 0x14F0

    # 6. Execute Solver
    simgr = project.factory.simgr(state)
    print(f"[*] Solving path dynamically toward: {hex(success_address)}")
    simgr.explore(find=success_address, avoid=failure_address)

    if simgr.found:
        solved_state = simgr.found[0]
        # Pull resolved bytes associated with input buffer pointer (mapped from target register)
        target_buf_ptr = int(snapshot_data["target_ptr"], 16)
        resolved_bytes = solved_state.solver.eval(solved_state.memory.load(target_buf_ptr, snapshot_data["length"]), cast_to=bytes)
        print(f"\033[92m[+] Constraints Resolved: {resolved_bytes.hex()}\033[0m")
        return list(resolved_bytes)
    else:
        print("[-] Symbolic execution failed to resolve constraints.")
        return list(b"\x00" * snapshot_data["length"])


def on_message(message, data):
    if message['type'] == 'send':
        payload = message['payload']
        if payload.get("type") == "STATE_PACKET":
            # Pass carving data off to angr
            solved_bytes = handle_symbolic_solving(payload)
            
            # Resume suspended Frida thread with solution payload
            script.post({
                "type": "SOLVE_REPLY", 
                "payload": solved_bytes, 
                "target_ptr": payload["target_ptr"]
            })
    else:
        print(message)


def main():
    if not os.path.exists(TARGET_SO_PATH):
        sys.exit(f"[-] Missing local compiled binary path: {TARGET_SO_PATH}")

    device = frida.get_usb_device()
    pid = device.spawn([PACKAGE_NAME])
    session = device.attach(pid)
    
    global script
    with open("concolic_engine/agent.js", "r") as f:
        script = session.create_script(f.read())
        
    script.on('message', on_message)
    script.load()
    device.resume(pid)
    sys.stdin.read()

if __name__ == "__main__":
    main()
