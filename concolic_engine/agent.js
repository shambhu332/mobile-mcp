// concolic_engine/agent.js

const TARGET_SO = "libnative-lib.so";
const TARGET_FUNCTION = "Java_com_example_app_NativeBridge_verifySecureToken";

Java.perform(function() {
    console.log("[*] Injecting Anti-Analysis and State Carver...");
    neutralizeAntiAnalysis();
    instrumentConcolicGate();
});

/**
 * Bypasses root checks, debugger attachments, and system sandboxing.
 */
function neutralizeAntiAnalysis() {
    const LIBC_NAME = "libc.so";

    // Bypass ptrace self-debugging locks
    const ptracePtr = Module.findExportByName(LIBC_NAME, "ptrace");
    if (ptracePtr) {
        Interceptor.attach(ptracePtr, {
            onEnter: function(args) {
                if (args[0].toInt32() === 0) { // PTRACE_TRACEME
                    console.log("[!] Anti-Debug bypass: neutralizing PTRACE_TRACEME.");
                    this.bypass = true;
                }
            },
            onLeave: function(retval) {
                if (this.bypass) retval.replace(0);
            }
        });
    }

    // Spoof TracerPid detection in /proc/self/status
    const readPtr = Module.findExportByName(LIBC_NAME, "read");
    if (readPtr) {
        Interceptor.attach(readPtr, {
            onLeave: function(retval) {
                const size = retval.toInt32();
                if (size > 0) {
                    const buf = this.context.x1; // x1 holds buffer in ARM64 ABI
                    const content = buf.readUtf8String(size);
                    if (content && content.includes("TracerPid:")) {
                        const cleanContent = content.replace(/TracerPid:\s+\d+/g, "TracerPid:\t0");
                        buf.writeUtf8String(cleanContent);
                    }
                }
            }
        });
    }
}

/**
 * Captures registers, stack memory, and heap structures, then waits for solver input.
 */
function instrumentConcolicGate() {
    const baseAddr = Module.findBaseAddress(TARGET_SO);
    if (!baseAddr) {
        // Wait for library load if not already loaded
        Interceptor.attach(Module.findExportByName(null, "android_dlopen_ext"), {
            onLeave: function() {
                instrumentConcolicGate();
            }
        });
        return;
    }

    const targetAddr = Module.findExportByName(TARGET_SO, TARGET_FUNCTION);
    if (!targetAddr) return;

    console.log("[+] Targeted gate found: " + targetAddr);

    Interceptor.attach(targetAddr, {
        onEnter: function(args) {
            console.log("\n[!] ---> ROADBLOCK ENCOUNTERED <---");
            const ctx = this.context;
            
            const registers = [
                'x0', 'x1', 'x2', 'x3', 'x4', 'x5', 'x6', 'x7', 'x8', 'x9',
                'x10', 'x11', 'x12', 'x13', 'x14', 'x15', 'x16', 'x17', 'x18',
                'x19', 'x20', 'x21', 'x22', 'x23', 'x24', 'x25', 'x26', 'x27',
                'x28', 'fp', 'lr', 'sp', 'pc'
            ];

            const serializedRegs = {};
            const heapPages = [];
            const mappedTracker = new Set();

            // 1. Serialize CPU registers and identify memory ranges
            registers.forEach(reg => {
                const val = ctx[reg];
                serializedRegs[reg] = val.toString();

                if (val.compare(ptr("0x1000")) > 0) {
                    const memRange = Process.findRangeByAddress(val);
                    if (memRange !== null && memRange.protection.indexOf('x') === -1) {
                        const pageBase = memRange.base;
                        const pageSize = memRange.size;
                        const pageKey = pageBase.toString();

                        if (!mappedTracker.has(pageKey)) {
                            mappedTracker.add(pageKey);
                            try {
                                const rawMemory = pageBase.readByteArray(pageSize);
                                heapPages.push({
                                    base: pageKey,
                                    size: pageSize,
                                    protection: memRange.protection,
                                    data: Array.from(new Uint8Array(rawMemory))
                                });
                            } catch (e) {
                                // Skip protected pages
                            }
                        }
                    }
                }
            });

            // 2. Transmit State Packet to orchestrator
            send({
                type: "STATE_PACKET",
                registers: serializedRegs,
                pages: heapPages,
                length: 32, // Length of memory verification buffer
                target_ptr: args[2].toString() // Store pointer to dynamic user-controlled input buffer
            });

            // 3. Suspend JNI Thread and wait for angr calculations
            console.log("[*] JNI Thread suspended. Rebuilding virtual memory in Python...");
            const reply = recv("SOLVE_REPLY", function(message) {
                const solvedBytes = message.payload;
                console.log("[+] Solution received! Overwriting memory buffer...");
                
                // Write solved bytes directly back into target memory buffer
                const targetBuf = ptr(message.target_ptr);
                targetBuf.writeByteArray(solvedBytes);
            });
            
            reply.wait();
            console.log("[+] Thread resumed with valid parameters.\n");
        }
    });
}
