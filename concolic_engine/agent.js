// concolic_engine/agent.js

const RAW_CONFIG = "__MSE_AGENT_CONFIG_JSON__";

function loadConfig() {
    const defaults = {
        targetSo: "libnative-lib.so",
        targetFunction: "Java_com_example_app_NativeBridge_verifySecureToken",
        inputArgIndex: 2,
        symbolicLength: 32,
        maxPages: 48,
        maxPageBytes: 65536,
        enableApiHooks: true,
        enableCryptoHooks: true,
        enableNativeHooks: true,
        enableAntiAnalysisBypass: true,
        enableConcolicGate: true
    };

    try {
        if (typeof RAW_CONFIG === "string" && RAW_CONFIG.indexOf("__MSE_AGENT_CONFIG_JSON__") !== -1) {
            return defaults;
        }

        const provided = typeof RAW_CONFIG === "string" ? JSON.parse(RAW_CONFIG) : RAW_CONFIG;
        if (provided && typeof provided === "object") {
            Object.keys(provided).forEach(function(key) {
                defaults[key] = provided[key];
            });
        }
    } catch (e) {
        sendEvent("agent_error", {
            where: "loadConfig",
            error: String(e)
        });
    }

    return defaults;
}

const CONFIG = loadConfig();
let gateInstalled = false;
let dlopenHookInstalled = false;
const nativeHooked = {};

function sendEvent(kind, payload) {
    try {
        send({
            type: "API_EVENT",
            kind: kind,
            time: Date.now(),
            pid: Process.id,
            arch: Process.arch,
            payload: payload || {}
        });
    } catch (e) {
        // Keep instrumentation non-fatal.
    }
}

function asString(value) {
    try {
        if (value === null || value === undefined) {
            return null;
        }

        return String(value);
    } catch (e) {
        return "<unprintable>";
    }
}

function javaBytesToHex(bytes, limit) {
    if (!bytes) {
        return null;
    }

    const max = Math.min(bytes.length, limit || 64);
    const out = [];
    for (let i = 0; i < max; i++) {
        let value = bytes[i];
        if (value < 0) {
            value += 256;
        }
        out.push(("0" + value.toString(16)).slice(-2));
    }

    if (bytes.length > max) {
        out.push("...");
    }

    return out.join("");
}

function nativeBytesToHex(ptrValue, size, limit) {
    try {
        if (ptrValue.isNull() || size <= 0) {
            return null;
        }

        const max = Math.min(size, limit || 64);
        const bytes = ptrValue.readByteArray(max);
        return javaBytesToHex(Array.from(new Uint8Array(bytes)), max) + (size > max ? "..." : "");
    } catch (e) {
        return null;
    }
}

function findExport(moduleName, exportName) {
    try {
        if (typeof Module.findExportByName === "function") {
            return Module.findExportByName(moduleName, exportName);
        }
    } catch (e) {
        // Try newer Frida APIs below.
    }

    try {
        if (moduleName === null && typeof Module.findGlobalExportByName === "function") {
            return Module.findGlobalExportByName(exportName);
        }
    } catch (e) {
        // Continue to module lookup.
    }

    try {
        const moduleObj = Process.getModuleByName(moduleName);
        if (moduleObj && typeof moduleObj.findExportByName === "function") {
            return moduleObj.findExportByName(exportName);
        }
    } catch (e) {
        return null;
    }

    return null;
}

function findModuleBase(moduleName) {
    try {
        if (typeof Module.findBaseAddress === "function") {
            return Module.findBaseAddress(moduleName);
        }
    } catch (e) {
        // Try Process module lookup below.
    }

    try {
        const moduleObj = Process.getModuleByName(moduleName);
        return moduleObj ? moduleObj.base : null;
    } catch (e) {
        return null;
    }
}

function classIfAvailable(name) {
    try {
        return Java.use(name);
    } catch (e) {
        return null;
    }
}

function hookOverloads(clazz, methodName, callback) {
    if (!clazz || !clazz[methodName]) {
        return;
    }

    clazz[methodName].overloads.forEach(function(overload) {
        overload.implementation = function() {
            return callback.call(this, overload, arguments);
        };
    });
}

function installApiVisibilityHooks() {
    Java.perform(function() {
        sendEvent("agent_status", { message: "installing Java API visibility hooks" });

        const WebView = classIfAvailable("android.webkit.WebView");
        if (WebView) {
            hookOverloads(WebView, "loadUrl", function(overload, args) {
                sendEvent("webview.loadUrl", {
                    url: asString(args[0]),
                    overload: overload.argumentTypes.map(function(t) { return t.name; })
                });
                return overload.apply(this, args);
            });

            hookOverloads(WebView, "postUrl", function(overload, args) {
                sendEvent("webview.postUrl", {
                    url: asString(args[0]),
                    body_hex: javaBytesToHex(args[1], 96)
                });
                return overload.apply(this, args);
            });
        }

        const URL = classIfAvailable("java.net.URL");
        if (URL) {
            hookOverloads(URL, "openConnection", function(overload, args) {
                sendEvent("network.URL.openConnection", { url: asString(this.toString()) });
                return overload.apply(this, args);
            });
        }

        const HttpURLConnection = classIfAvailable("java.net.HttpURLConnection");
        if (HttpURLConnection) {
            hookOverloads(HttpURLConnection, "connect", function(overload, args) {
                sendEvent("network.HttpURLConnection.connect", {
                    url: asString(this.getURL()),
                    method: asString(this.getRequestMethod())
                });
                return overload.apply(this, args);
            });

            hookOverloads(HttpURLConnection, "getInputStream", function(overload, args) {
                sendEvent("network.HttpURLConnection.getInputStream", {
                    url: asString(this.getURL()),
                    method: asString(this.getRequestMethod())
                });
                return overload.apply(this, args);
            });

            hookOverloads(HttpURLConnection, "getOutputStream", function(overload, args) {
                sendEvent("network.HttpURLConnection.getOutputStream", {
                    url: asString(this.getURL()),
                    method: asString(this.getRequestMethod())
                });
                return overload.apply(this, args);
            });
        }

        const OkHttpClient = classIfAvailable("okhttp3.OkHttpClient");
        if (OkHttpClient) {
            hookOverloads(OkHttpClient, "newCall", function(overload, args) {
                const request = args[0];
                sendEvent("network.okhttp.newCall", {
                    url: asString(request.url()),
                    method: asString(request.method())
                });
                return overload.apply(this, args);
            });
        }

        const CertificatePinner = classIfAvailable("okhttp3.CertificatePinner");
        if (CertificatePinner) {
            hookOverloads(CertificatePinner, "check", function(overload, args) {
                sendEvent("network.okhttp.CertificatePinner.check.bypass", {
                    host: asString(args[0]),
                    overload: overload.argumentTypes.map(function(t) { return t.name; })
                });
                return;
            });
        }

        const TrustManagerImpl = classIfAvailable("com.android.org.conscrypt.TrustManagerImpl");
        if (TrustManagerImpl) {
            hookOverloads(TrustManagerImpl, "checkTrustedRecursive", function(overload, args) {
                sendEvent("network.conscrypt.checkTrustedRecursive", {
                    host: asString(args[2] || args[3] || null),
                    overload: overload.argumentTypes.map(function(t) { return t.name; })
                });
                return overload.apply(this, args);
            });
        }
    });
}

function installCryptoHooks() {
    Java.perform(function() {
        sendEvent("agent_status", { message: "installing Java crypto hooks" });

        const SecretKeySpec = classIfAvailable("javax.crypto.spec.SecretKeySpec");
        if (SecretKeySpec) {
            const initBytes = SecretKeySpec.$init.overload("[B", "java.lang.String");
            initBytes.implementation = function(keyBytes, algorithm) {
                sendEvent("crypto.SecretKeySpec", {
                    algorithm: asString(algorithm),
                    key_hex: javaBytesToHex(keyBytes, 96),
                    key_length: keyBytes ? keyBytes.length : 0
                });
                return initBytes.call(this, keyBytes, algorithm);
            };
        }

        const IvParameterSpec = classIfAvailable("javax.crypto.spec.IvParameterSpec");
        if (IvParameterSpec) {
            const initBytes = IvParameterSpec.$init.overload("[B");
            initBytes.implementation = function(ivBytes) {
                sendEvent("crypto.IvParameterSpec", {
                    iv_hex: javaBytesToHex(ivBytes, 96),
                    iv_length: ivBytes ? ivBytes.length : 0
                });
                return initBytes.call(this, ivBytes);
            };
        }

        const Cipher = classIfAvailable("javax.crypto.Cipher");
        if (Cipher) {
            hookOverloads(Cipher, "getInstance", function(overload, args) {
                sendEvent("crypto.Cipher.getInstance", { transformation: asString(args[0]) });
                return overload.apply(this, args);
            });

            hookOverloads(Cipher, "init", function(overload, args) {
                let keyInfo = null;
                try {
                    const key = args.length > 1 ? args[1] : null;
                    keyInfo = key ? {
                        algorithm: asString(key.getAlgorithm()),
                        format: asString(key.getFormat()),
                        encoded_hex: javaBytesToHex(key.getEncoded(), 96)
                    } : null;
                } catch (e) {
                    keyInfo = { error: String(e) };
                }

                sendEvent("crypto.Cipher.init", {
                    opmode: args.length > 0 ? Number(args[0]) : null,
                    algorithm: asString(this.getAlgorithm()),
                    key: keyInfo,
                    overload: overload.argumentTypes.map(function(t) { return t.name; })
                });
                return overload.apply(this, args);
            });

            hookOverloads(Cipher, "update", function(overload, args) {
                sendEvent("crypto.Cipher.update", {
                    algorithm: asString(this.getAlgorithm()),
                    input_hex: args.length > 0 ? javaBytesToHex(args[0], 96) : null,
                    overload: overload.argumentTypes.map(function(t) { return t.name; })
                });
                return overload.apply(this, args);
            });

            hookOverloads(Cipher, "doFinal", function(overload, args) {
                sendEvent("crypto.Cipher.doFinal.enter", {
                    algorithm: asString(this.getAlgorithm()),
                    input_hex: args.length > 0 ? javaBytesToHex(args[0], 96) : null,
                    overload: overload.argumentTypes.map(function(t) { return t.name; })
                });
                const result = overload.apply(this, args);
                sendEvent("crypto.Cipher.doFinal.leave", {
                    algorithm: asString(this.getAlgorithm()),
                    output_hex: javaBytesToHex(result, 96)
                });
                return result;
            });
        }

        const MessageDigest = classIfAvailable("java.security.MessageDigest");
        if (MessageDigest) {
            hookOverloads(MessageDigest, "getInstance", function(overload, args) {
                sendEvent("crypto.MessageDigest.getInstance", { algorithm: asString(args[0]) });
                return overload.apply(this, args);
            });

            hookOverloads(MessageDigest, "digest", function(overload, args) {
                sendEvent("crypto.MessageDigest.digest.enter", {
                    algorithm: asString(this.getAlgorithm()),
                    input_hex: args.length > 0 ? javaBytesToHex(args[0], 96) : null
                });
                const result = overload.apply(this, args);
                sendEvent("crypto.MessageDigest.digest.leave", {
                    algorithm: asString(this.getAlgorithm()),
                    output_hex: javaBytesToHex(result, 96)
                });
                return result;
            });
        }

        const Mac = classIfAvailable("javax.crypto.Mac");
        if (Mac) {
            hookOverloads(Mac, "getInstance", function(overload, args) {
                sendEvent("crypto.Mac.getInstance", { algorithm: asString(args[0]) });
                return overload.apply(this, args);
            });

            hookOverloads(Mac, "doFinal", function(overload, args) {
                sendEvent("crypto.Mac.doFinal.enter", {
                    algorithm: asString(this.getAlgorithm()),
                    input_hex: args.length > 0 ? javaBytesToHex(args[0], 96) : null
                });
                const result = overload.apply(this, args);
                sendEvent("crypto.Mac.doFinal.leave", {
                    algorithm: asString(this.getAlgorithm()),
                    output_hex: javaBytesToHex(result, 96)
                });
                return result;
            });
        }

        const KeyStore = classIfAvailable("java.security.KeyStore");
        if (KeyStore) {
            hookOverloads(KeyStore, "getInstance", function(overload, args) {
                sendEvent("crypto.KeyStore.getInstance", {
                    type: asString(args[0]),
                    overload: overload.argumentTypes.map(function(t) { return t.name; })
                });
                return overload.apply(this, args);
            });

            hookOverloads(KeyStore, "getKey", function(overload, args) {
                sendEvent("crypto.KeyStore.getKey", { alias: asString(args[0]) });
                return overload.apply(this, args);
            });

            hookOverloads(KeyStore, "setEntry", function(overload, args) {
                sendEvent("crypto.KeyStore.setEntry", { alias: asString(args[0]) });
                return overload.apply(this, args);
            });
        }
    });
}

function neutralizeAntiAnalysis() {
    const ptracePtr = findExport("libc.so", "ptrace");
    if (ptracePtr) {
        Interceptor.attach(ptracePtr, {
            onEnter: function(args) {
                if (args[0].toInt32() === 0) {
                    sendEvent("anti_analysis.ptrace.bypass", { request: "PTRACE_TRACEME" });
                    this.bypass = true;
                }
            },
            onLeave: function(retval) {
                if (this.bypass) {
                    retval.replace(0);
                }
            }
        });
    }

    const readPtr = findExport("libc.so", "read");
    if (readPtr) {
        Interceptor.attach(readPtr, {
            onEnter: function(args) {
                this.buf = args[1];
            },
            onLeave: function(retval) {
                const size = retval.toInt32();
                if (size <= 0 || !this.buf) {
                    return;
                }

                try {
                    const content = this.buf.readUtf8String(size);
                    if (content && content.indexOf("TracerPid:") !== -1) {
                        const cleanContent = content.replace(/TracerPid:\s+\d+/g, "TracerPid:\t0");
                        this.buf.writeUtf8String(cleanContent);
                        sendEvent("anti_analysis.tracerpid.bypass", {});
                    }
                } catch (e) {
                    // Non-text read; ignore.
                }
            }
        });
    }
}

function installNativeCryptoHooks() {
    const functions = [
        { module: null, name: "SSL_write", args: ["ssl", "buf", "num"] },
        { module: null, name: "SSL_read", args: ["ssl", "buf", "num"] },
        { module: null, name: "EVP_EncryptInit_ex", args: [] },
        { module: null, name: "EVP_DecryptInit_ex", args: [] },
        { module: null, name: "EVP_CipherInit_ex", args: [] },
        { module: null, name: "AES_set_encrypt_key", args: [] },
        { module: null, name: "AES_set_decrypt_key", args: [] }
    ];

    functions.forEach(function(item) {
        const addr = findExport(item.module, item.name);
        if (!addr) {
            return;
        }

        const hookKey = item.name + ":" + addr.toString();
        if (nativeHooked[hookKey]) {
            return;
        }
        nativeHooked[hookKey] = true;

        Interceptor.attach(addr, {
            onEnter: function(args) {
                const payload = { function: item.name };
                if (item.name === "SSL_write" || item.name === "SSL_read") {
                    const size = args[2].toInt32();
                    payload.length = size;
                    payload.buffer_hex = nativeBytesToHex(args[1], size, 96);
                }
                sendEvent("native." + item.name, payload);
            }
        });
    });
}

function registersForArch() {
    if (Process.arch === "arm64") {
        return ["x0", "x1", "x2", "x3", "x4", "x5", "x6", "x7", "x8", "x9", "x10", "x11", "x12", "x13", "x14", "x15", "x16", "x17", "x18", "x19", "x20", "x21", "x22", "x23", "x24", "x25", "x26", "x27", "x28", "fp", "lr", "sp", "pc"];
    }

    if (Process.arch === "arm") {
        return ["r0", "r1", "r2", "r3", "r4", "r5", "r6", "r7", "r8", "r9", "r10", "r11", "r12", "sp", "lr", "pc"];
    }

    if (Process.arch === "x64") {
        return ["rax", "rbx", "rcx", "rdx", "rsi", "rdi", "rbp", "rsp", "rip", "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15"];
    }

    if (Process.arch === "ia32") {
        return ["eax", "ebx", "ecx", "edx", "esi", "edi", "ebp", "esp", "eip"];
    }

    return [];
}

function getProgramCounter(ctx) {
    return ctx.pc || ctx.rip || ctx.eip;
}

function carvePointedPage(pointerValue, heapPages, mappedTracker) {
    if (!pointerValue || pointerValue.compare(ptr("0x1000")) <= 0) {
        return;
    }

    const memRange = Process.findRangeByAddress(pointerValue);
    if (memRange === null || memRange.protection.indexOf("x") !== -1) {
        return;
    }

    const pageKey = memRange.base.toString();
    if (mappedTracker[pageKey] || heapPages.length >= CONFIG.maxPages) {
        return;
    }

    mappedTracker[pageKey] = true;
    const readSize = Math.min(memRange.size, CONFIG.maxPageBytes);
    try {
        const rawMemory = memRange.base.readByteArray(readSize);
        heapPages.push({
            base: pageKey,
            size: readSize,
            protection: memRange.protection,
            data: Array.from(new Uint8Array(rawMemory))
        });
    } catch (e) {
        sendEvent("concolic.page.skip", {
            base: pageKey,
            size: readSize,
            error: String(e)
        });
    }
}

function installDlopenHook() {
    if (dlopenHookInstalled) {
        return;
    }

    const dlopen = findExport(null, "android_dlopen_ext") || findExport(null, "dlopen");
    if (!dlopen) {
        return;
    }

    dlopenHookInstalled = true;
    Interceptor.attach(dlopen, {
        onLeave: function() {
            if (CONFIG.enableNativeHooks) {
                installNativeCryptoHooks();
            }
            instrumentConcolicGate();
        }
    });
}

function instrumentConcolicGate() {
    if (gateInstalled) {
        return;
    }

    const baseAddr = findModuleBase(CONFIG.targetSo);
    if (!baseAddr) {
        installDlopenHook();
        return;
    }

    const targetAddr = findExport(CONFIG.targetSo, CONFIG.targetFunction);
    if (!targetAddr) {
        sendEvent("concolic.target.missing", {
            targetSo: CONFIG.targetSo,
            targetFunction: CONFIG.targetFunction
        });
        return;
    }

    gateInstalled = true;
    sendEvent("concolic.target.found", {
        targetSo: CONFIG.targetSo,
        targetFunction: CONFIG.targetFunction,
        address: targetAddr.toString(),
        base: baseAddr.toString()
    });

    Interceptor.attach(targetAddr, {
        onEnter: function(args) {
            const ctx = this.context;
            const registers = {};
            const heapPages = [];
            const mappedTracker = {};
            const regNames = registersForArch();

            regNames.forEach(function(reg) {
                const value = ctx[reg];
                if (!value) {
                    return;
                }

                registers[reg] = value.toString();
                carvePointedPage(value, heapPages, mappedTracker);
            });

            const pc = getProgramCounter(ctx);
            if (pc) {
                registers.pc = pc.toString();
            }

            const targetPtr = args[CONFIG.inputArgIndex];
            carvePointedPage(targetPtr, heapPages, mappedTracker);

            send({
                type: "STATE_PACKET",
                architecture: Process.arch,
                target_so: CONFIG.targetSo,
                target_function: CONFIG.targetFunction,
                registers: registers,
                pages: heapPages,
                length: CONFIG.symbolicLength,
                target_ptr: targetPtr.toString()
            });

            const reply = recv("SOLVE_REPLY", function(message) {
                try {
                    const solvedBytes = message.payload || [];
                    ptr(message.target_ptr).writeByteArray(solvedBytes);
                    sendEvent("concolic.solution.applied", {
                        target_ptr: message.target_ptr,
                        length: solvedBytes.length
                    });
                } catch (e) {
                    sendEvent("concolic.solution.apply_error", { error: String(e) });
                }
            });

            reply.wait();
        }
    });
}

function installJavaHooks() {
    sendEvent("agent_status", {
        message: "mobile security engine agent loaded",
        config: CONFIG
    });

    if (CONFIG.enableApiHooks) {
        installApiVisibilityHooks();
    }

    if (CONFIG.enableCryptoHooks) {
        installCryptoHooks();
    }

    if (CONFIG.enableConcolicGate) {
        instrumentConcolicGate();
    }
}

if (CONFIG.enableNativeHooks) {
    installNativeCryptoHooks();
}

if (CONFIG.enableAntiAnalysisBypass) {
    neutralizeAntiAnalysis();
}

function waitForJavaAndInstall(remainingAttempts) {
    if (typeof Java !== "undefined" && Java.available) {
        Java.perform(installJavaHooks);
        return;
    }

    if (remainingAttempts > 0) {
        setTimeout(function() {
            waitForJavaAndInstall(remainingAttempts - 1);
        }, 100);
        return;
    }

    sendEvent("agent_status", {
        message: "Java runtime unavailable; native hooks only",
        config: CONFIG
    });

    if (CONFIG.enableConcolicGate) {
        instrumentConcolicGate();
    }
}

waitForJavaAndInstall(50);
