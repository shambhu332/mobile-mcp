import { execFile } from "child_process";
import { promisify } from "util";
import path from "path";
import { validatePackageName } from "../utils";

const execFileAsync = promisify(execFile);

// Path resolution pointing directly to the root of the single repository
const REPO_ROOT = path.resolve(__dirname, "../..");
const PROVISION_EMULATOR_SCRIPT = path.join(REPO_ROOT, "ci/provision_emulator.sh");
const RUN_FRIDA_SCRIPT = path.join(REPO_ROOT, "ci/setup_frida_server.sh");
const AUTO_ANALYZE_SCRIPT = path.join(REPO_ROOT, "ci/analyze_apps.sh");
const ORCHESTRATOR_PY = path.join(REPO_ROOT, "concolic_engine/orchestrator.py");
const PYTHON_BIN = process.env.PYTHON || "python3";
const EXEC_OPTIONS = {
	cwd: REPO_ROOT,
	maxBuffer: 1024 * 1024 * 16,
};

export const SECURITY_TOOLS = [
	{
		name: "security_provision_emulator",
		description: "Provisions a rooted Genymotion emulator with a writable system trust store, mitmproxy CA, global proxy, and mitmdump capture.",
		inputSchema: { type: "object", properties: {}, required: [] }
	},
	{
		name: "security_setup_frida_environment",
		description: "Launches and verifies the Frida-Server on the connected Android emulator or physical device.",
		inputSchema: { type: "object", properties: {}, required: [] }
	},
	{
		name: "security_solve_concolic_gate",
		description: "Spawns the target app under a dynamic Frida session, emits API/crypto/network telemetry, and optionally executes angr with path-explosion controls.",
		inputSchema: {
			type: "object",
			properties: {
				packageName: { type: "string", description: "Target Android package name." },
				nativeLibraryPath: { type: "string", description: "Local native library path for angr." },
				targetSo: { type: "string", description: "Loaded native library name to instrument." },
				targetSymbol: { type: "string", description: "Exported native function symbol to intercept." },
				successOffset: { type: "string", description: "Success offset from target symbol, e.g. 0x14C2." },
				failureOffset: { type: "string", description: "Failure offset from target symbol, e.g. 0x14F0." },
				inputArgIndex: { type: "number", description: "Native function argument index containing input pointer." },
				inputLength: { type: "number", description: "Symbolic input length in bytes." },
				eventLogPath: { type: "string", description: "JSONL output path for runtime telemetry." },
				fridaRemote: { type: "string", description: "Remote Frida host:port, e.g. 127.0.0.1:27042." },
				durationSeconds: { type: "number", description: "Run instrumentation for N seconds, then detach." },
				solveTimeoutSeconds: { type: "number", description: "Maximum seconds per symbolic solve." },
				maxSteps: { type: "number", description: "Maximum angr steps per solve." },
				maxActive: { type: "number", description: "Maximum active states retained per step." },
				disableSolving: { type: "boolean", description: "Collect API telemetry without invoking angr." },
			},
			required: ["packageName"]
		}
	},
	{
		name: "security_auto_analyze_apps",
		description: "End-to-end Android security automation for APK paths, APK directories, package names, target lists, or all installed user apps. Provisions proxy trust, starts Frida, installs APKs, extracts native libraries, discovers candidate symbols, captures runtime telemetry, and writes reports.",
		inputSchema: {
			type: "object",
			properties: {
				targetPath: { type: "string", description: "Single APK file, APK directory, package name, or text file containing targets." },
				targets: { type: "array", items: { type: "string" }, description: "APK files, APK directories, package names, or target-list files." },
				apkPaths: { type: "array", items: { type: "string" }, description: "APK files to install and analyze." },
				apkDirs: { type: "array", items: { type: "string" }, description: "Directories of APK files to analyze recursively." },
				packageName: { type: "string", description: "Single already installed Android package name." },
				packageNames: { type: "array", items: { type: "string" }, description: "Already installed Android package names." },
				targetListPath: { type: "string", description: "Text file containing APK paths, APK directories, or package names." },
				outputDir: { type: "string", description: "Directory for reports and artifacts." },
				fridaRemote: { type: "string", description: "Remote Frida host:port, e.g. 127.0.0.1:27042." },
				durationSeconds: { type: "number", description: "Runtime API/crypto trace duration per app." },
				nativeProbeDurationSeconds: { type: "number", description: "Duration per native candidate probe." },
				nativeProbeLimit: { type: "number", description: "Maximum native candidate symbols to probe per app. Use 0 to disable." },
				maxSymbolsPerLib: { type: "number", description: "Maximum scored native symbols retained per library." },
				inputArgIndex: { type: "number", description: "Native argument index containing the target input pointer." },
				inputLength: { type: "number", description: "Symbolic input length for native probes." },
				adbSerial: { type: "string", description: "ADB serial/device ID." },
				installedUserApps: { type: "boolean", description: "Analyze all third-party packages currently installed on the device." },
				skipProvision: { type: "boolean", description: "Skip emulator/proxy provisioning." },
				skipFrida: { type: "boolean", description: "Skip frida-server setup." },
				skipInstall: { type: "boolean", description: "Do not install APK targets before analysis." },
				skipRuntime: { type: "boolean", description: "Only extract native metadata; do not run Frida runtime tracing." },
				enableSolving: { type: "boolean", description: "Enable angr solving for native probes when success target data is supplied." },
				strict: { type: "boolean", description: "Exit non-zero if any target fails." },
				successOffset: { type: "string", description: "Success offset from probed target symbol." },
				failureOffset: { type: "string", description: "Failure offset from probed target symbol." },
				successAddress: { type: "string", description: "Absolute success address." },
				failureAddress: { type: "string", description: "Absolute failure address." },
			},
			required: []
		}
	}
];

function appendOptionalString(args: string[], flag: string, value: unknown): void {
	if (typeof value === "string" && value.trim() !== "") {
		args.push(flag, value.trim());
	}
}

function appendOptionalNumber(args: string[], flag: string, value: unknown): void {
	if (typeof value === "number" && Number.isFinite(value)) {
		args.push(flag, String(value));
	}
}

function appendOptionalBoolean(args: string[], flag: string, value: unknown): void {
	if (value === true) {
		args.push(flag);
	}
}

function appendRepeatedString(args: string[], flag: string, values: unknown): void {
	if (!Array.isArray(values)) {
		return;
	}

	for (const value of values) {
		if (typeof value === "string" && value.trim() !== "") {
			args.push(flag, value.trim());
		}
	}
}

async function runCommand(command: string, args: string[]): Promise<string> {
	const { stdout, stderr } = await execFileAsync(command, args, EXEC_OPTIONS);
	const output = [stdout, stderr].filter(Boolean).join("\n").trim();
	return output || "(no output)";
}

function buildConcolicArgs(toolArgs: any): string[] {
	const packageName = String(toolArgs.packageName || "");
	validatePackageName(packageName);

	const args = [ORCHESTRATOR_PY, "--package", packageName];
	appendOptionalString(args, "--binary", toolArgs.nativeLibraryPath);
	appendOptionalString(args, "--target-so", toolArgs.targetSo);
	appendOptionalString(args, "--target-symbol", toolArgs.targetSymbol);
	appendOptionalString(args, "--success-offset", toolArgs.successOffset);
	appendOptionalString(args, "--failure-offset", toolArgs.failureOffset);
	appendOptionalString(args, "--event-log", toolArgs.eventLogPath);
	appendOptionalString(args, "--remote", toolArgs.fridaRemote);
	appendOptionalNumber(args, "--input-arg-index", toolArgs.inputArgIndex);
	appendOptionalNumber(args, "--length", toolArgs.inputLength);
	appendOptionalNumber(args, "--duration", toolArgs.durationSeconds);
	appendOptionalNumber(args, "--solve-timeout", toolArgs.solveTimeoutSeconds);
	appendOptionalNumber(args, "--max-steps", toolArgs.maxSteps);
	appendOptionalNumber(args, "--max-active", toolArgs.maxActive);

	if (toolArgs.disableSolving === true) {
		args.push("--disable-solving");
	}

	return args;
}

function buildAutoAnalyzeArgs(toolArgs: any): string[] {
	const args: string[] = [];
	const positionalTargets: string[] = [];

	appendOptionalString(args, "--target-list", toolArgs.targetListPath);
	appendOptionalString(args, "--output-dir", toolArgs.outputDir);
	appendOptionalString(args, "--frida-remote", toolArgs.fridaRemote);
	appendOptionalString(args, "--success-offset", toolArgs.successOffset);
	appendOptionalString(args, "--failure-offset", toolArgs.failureOffset);
	appendOptionalString(args, "--success-address", toolArgs.successAddress);
	appendOptionalString(args, "--failure-address", toolArgs.failureAddress);
	appendOptionalString(args, "--adb-serial", toolArgs.adbSerial);
	appendOptionalNumber(args, "--duration", toolArgs.durationSeconds);
	appendOptionalNumber(args, "--native-probe-duration", toolArgs.nativeProbeDurationSeconds);
	appendOptionalNumber(args, "--native-probe-limit", toolArgs.nativeProbeLimit);
	appendOptionalNumber(args, "--max-symbols-per-lib", toolArgs.maxSymbolsPerLib);
	appendOptionalNumber(args, "--input-arg-index", toolArgs.inputArgIndex);
	appendOptionalNumber(args, "--length", toolArgs.inputLength);
	appendOptionalBoolean(args, "--installed-user-apps", toolArgs.installedUserApps);
	appendOptionalBoolean(args, "--skip-provision", toolArgs.skipProvision);
	appendOptionalBoolean(args, "--skip-frida", toolArgs.skipFrida);
	appendOptionalBoolean(args, "--skip-install", toolArgs.skipInstall);
	appendOptionalBoolean(args, "--skip-runtime", toolArgs.skipRuntime);
	appendOptionalBoolean(args, "--enable-solving", toolArgs.enableSolving);
	appendOptionalBoolean(args, "--strict", toolArgs.strict);

	if (typeof toolArgs.packageName === "string" && toolArgs.packageName.trim() !== "") {
		const packageName = toolArgs.packageName.trim();
		validatePackageName(packageName);
		args.push("--package", packageName);
	}

	if (Array.isArray(toolArgs.packageNames)) {
		for (const value of toolArgs.packageNames) {
			if (typeof value === "string" && value.trim() !== "") {
				const packageName = value.trim();
				validatePackageName(packageName);
				args.push("--package", packageName);
			}
		}
	}

	if (typeof toolArgs.targetPath === "string" && toolArgs.targetPath.trim() !== "") {
		positionalTargets.push(toolArgs.targetPath.trim());
	}

	if (Array.isArray(toolArgs.targets)) {
		for (const value of toolArgs.targets) {
			if (typeof value === "string" && value.trim() !== "") {
				positionalTargets.push(value.trim());
			}
		}
	}

	appendRepeatedString(args, "--apk", toolArgs.apkPaths);
	appendRepeatedString(args, "--apk-dir", toolArgs.apkDirs);
	args.push(...positionalTargets);

	if (
		positionalTargets.length === 0 &&
		!toolArgs.targetListPath &&
		!toolArgs.packageName &&
		!(Array.isArray(toolArgs.packageNames) && toolArgs.packageNames.length > 0) &&
		!(Array.isArray(toolArgs.apkPaths) && toolArgs.apkPaths.length > 0) &&
		!(Array.isArray(toolArgs.apkDirs) && toolArgs.apkDirs.length > 0) &&
		toolArgs.installedUserApps !== true
	) {
		throw new Error("Provide targetPath, targets, packageName, packageNames, targetListPath, or installedUserApps.");
	}

	return args;
}

export async function handleSecurityToolCall(name: string, args: any) {
	switch (name) {
		case "security_provision_emulator": {
			try {
				console.error(`[*] Executing: ${PROVISION_EMULATOR_SCRIPT}`);
				const output = await runCommand("bash", [PROVISION_EMULATOR_SCRIPT]);
				return { content: [{ type: "text", text: `Emulator provisioning complete.\n${output}` }] };
			} catch (err: any) {
				return { isError: true, content: [{ type: "text", text: `Emulator provisioning failed: ${err.message}` }] };
			}
		}
		case "security_setup_frida_environment": {
			try {
				console.error(`[*] Executing: ${RUN_FRIDA_SCRIPT}`);
				const output = await runCommand("bash", [RUN_FRIDA_SCRIPT]);
				return { content: [{ type: "text", text: `Frida configuration complete.\n${output}` }] };
			} catch (err: any) {
				return { isError: true, content: [{ type: "text", text: `Frida setup failed: ${err.message}` }] };
			}
		}
		case "security_solve_concolic_gate": {
			try {
				const concolicArgs = buildConcolicArgs(args);
				console.error(`[*] Running concolic orchestrator for package: ${args.packageName}`);
				const output = await runCommand(PYTHON_BIN, concolicArgs);
				return { content: [{ type: "text", text: `Runtime analysis finished.\n${output}` }] };
			} catch (err: any) {
				return { isError: true, content: [{ type: "text", text: `Runtime analysis failed: ${err.message}` }] };
			}
		}
		case "security_auto_analyze_apps": {
			try {
				const autoAnalyzeArgs = buildAutoAnalyzeArgs(args);
				console.error(`[*] Running end-to-end mobile security automation`);
				const output = await runCommand("bash", [AUTO_ANALYZE_SCRIPT, ...autoAnalyzeArgs]);
				return { content: [{ type: "text", text: `Automation finished.\n${output}` }] };
			} catch (err: any) {
				return { isError: true, content: [{ type: "text", text: `Automation failed: ${err.message}` }] };
			}
		}
		default:
			throw new Error(`Tool ${name} not recognized.`);
	}
}
