import { execFile } from "child_process";
import { promisify } from "util";
import path from "path";
import { validatePackageName } from "../utils";

const execFileAsync = promisify(execFile);

// Path resolution pointing directly to the root of the single repository
const REPO_ROOT = path.resolve(__dirname, "../..");
const PROVISION_EMULATOR_SCRIPT = path.join(REPO_ROOT, "ci/provision_emulator.sh");
const RUN_FRIDA_SCRIPT = path.join(REPO_ROOT, "ci/setup_frida_server.sh");
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
		default:
			throw new Error(`Tool ${name} not recognized.`);
	}
}
