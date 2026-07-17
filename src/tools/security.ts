import { exec } from "child_process";
import { promisify } from "util";
import path from "path";

const execAsync = promisify(exec);

// Path resolution pointing directly to the root of the single repository
const REPO_ROOT = path.resolve(__dirname, "../..");
const RUN_FRIDA_SCRIPT = path.join(REPO_ROOT, "ci/setup_frida_server.sh");
const ORCHESTRATOR_PY = path.join(REPO_ROOT, "concolic_engine/orchestrator.py");

export const SECURITY_TOOLS = [
	{
		name: "security_setup_frida_environment",
		description: "Launches and verifies the Frida-Server on the connected Android emulator or physical device.",
		inputSchema: { type: "object", properties: {}, required: [] }
	},
	{
		name: "security_solve_concolic_gate",
		description: "Spawns the target app under a dynamic Frida session, maps volatile heap layers, and executes angr to solve JNI validation checkpoints.",
		inputSchema: {
			type: "object",
			properties: {
				packageName: { type: "string", description: "Target Android package name." }
			},
			required: ["packageName"]
		}
	}
];

export async function handleSecurityToolCall(name: string, args: any) {
	switch (name) {
		case "security_setup_frida_environment": {
			try {
				console.error(`[*] Executing: ${RUN_FRIDA_SCRIPT}`);
				const { stdout } = await execAsync(`bash ${RUN_FRIDA_SCRIPT}`);
				return { content: [{ type: "text", text: `Frida configuration complete.\nSTDOUT:\n${stdout}` }] };
			} catch (err: any) {
				return { isError: true, content: [{ type: "text", text: `Frida setup failed: ${err.message}` }] };
			}
		}
		case "security_solve_concolic_gate": {
			const { packageName } = args;
			try {
				console.error(`[*] Running concolic solver on: ${packageName}`);
				const { stdout } = await execAsync(`python3 ${ORCHESTRATOR_PY} --package ${packageName}`);
				return { content: [{ type: "text", text: `Solver finished.\nOutput:\n${stdout}` }] };
			} catch (err: any) {
				return { isError: true, content: [{ type: "text", text: `Solver execution failed: ${err.message}` }] };
			}
		}
		default:
			throw new Error(`Tool ${name} not recognized.`);
	}
}
