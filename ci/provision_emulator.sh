#!/bin/bash
# ci/provision_emulator.sh
set -euo pipefail

ADB_BIN="${ADB:-adb}"
MITM_PROXY_HOST="${MITM_PROXY_HOST:-10.0.3.2}"
MITM_PROXY_PORT="${MITM_PROXY_PORT:-8080}"
MITM_CERT="${MITM_CERT:-$HOME/.mitmproxy/mitmproxy-ca-cert.cer}"
MITM_PID_FILE="${MITM_PID_FILE:-/tmp/mobile-security-engine-mitmdump.pid}"
MITM_LOG_FILE="${MITM_LOG_FILE:-/tmp/mobile-security-engine-mitmdump.log}"
MITM_FLOW_FILE="${MITM_FLOW_FILE:-/tmp/mobile-security-engine-flows.mitm}"

ADB_CMD=("$ADB_BIN")
if [ -n "${ADB_SERIAL:-}" ]; then
	ADB_CMD+=("-s" "$ADB_SERIAL")
fi

echo "[*] Waiting for Android device..."
"${ADB_CMD[@]}" wait-for-device

echo "[*] Mounting Genymotion system partition as read-write..."
"${ADB_CMD[@]}" root
"${ADB_CMD[@]}" wait-for-device
if ! "${ADB_CMD[@]}" remount; then
	echo "[!] adb remount failed; trying direct /system remount fallback..."
	"${ADB_CMD[@]}" shell "mount -o rw,remount /system"
fi

if [ -f "$MITM_CERT" ]; then
	CERT_HASH=$(openssl x509 -inform PEM -subject_hash_old -in "$MITM_CERT" | head -n 1)
	echo "[*] Pushing MITM CA certificate ($CERT_HASH.0) to system trust store..."
	"${ADB_CMD[@]}" push "$MITM_CERT" "/system/etc/security/cacerts/$CERT_HASH.0"
	"${ADB_CMD[@]}" shell "chmod 644 /system/etc/security/cacerts/$CERT_HASH.0"
	echo "[+] CA certificate successfully pushed."
else
	echo "[!] Mitmproxy CA cert not found at $MITM_CERT. Run 'mitmproxy' once to generate it."
fi

echo "[*] Configuring Android global HTTP proxy to ${MITM_PROXY_HOST}:${MITM_PROXY_PORT}..."
"${ADB_CMD[@]}" shell "settings put global http_proxy ${MITM_PROXY_HOST}:${MITM_PROXY_PORT}"

if command -v mitmdump >/dev/null 2>&1; then
	if [ -f "$MITM_PID_FILE" ] && kill -0 "$(cat "$MITM_PID_FILE")" >/dev/null 2>&1; then
		echo "[*] mitmdump already running with PID $(cat "$MITM_PID_FILE")."
	else
		echo "[*] Starting mitmdump on 0.0.0.0:${MITM_PROXY_PORT}..."
		mitmdump \
			--listen-host 0.0.0.0 \
			--listen-port "$MITM_PROXY_PORT" \
			-w "$MITM_FLOW_FILE" \
			> "$MITM_LOG_FILE" 2>&1 &
		echo "$!" > "$MITM_PID_FILE"
		echo "[+] mitmdump started with PID $(cat "$MITM_PID_FILE")."
		echo "[*] Logs: $MITM_LOG_FILE"
		echo "[*] Flow capture: $MITM_FLOW_FILE"
	fi
else
	echo "[!] mitmdump is not installed or not in PATH; proxy was configured but capture was not started."
fi

echo "[*] Restarting system server to apply trust store modifications..."
"${ADB_CMD[@]}" shell "stop && start"
"${ADB_CMD[@]}" wait-for-device

echo "[+] Emulator provisioned successfully."
