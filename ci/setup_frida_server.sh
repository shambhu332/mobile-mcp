#!/bin/bash
# ci/setup_frida_server.sh
set -euo pipefail

ADB_BIN="${ADB:-adb}"
HOST_PYTHON="${PYTHON:-}"
if [ -z "$HOST_PYTHON" ] && [ -x ".venv/bin/python" ]; then
	HOST_PYTHON=".venv/bin/python"
fi
if [ -z "$HOST_PYTHON" ]; then
	HOST_PYTHON="python3"
fi

ADB_CMD=("$ADB_BIN")
if [ -n "${ADB_SERIAL:-}" ]; then
	ADB_CMD+=("-s" "$ADB_SERIAL")
fi

# Query runtime host version
FRIDA_VERSION=$("$HOST_PYTHON" -c "import frida; print(frida.__version__)")
echo "[*] Host Frida Version: $FRIDA_VERSION"

echo "[*] Waiting for Android device..."
"${ADB_CMD[@]}" wait-for-device

DEVICE_ABI=$("${ADB_CMD[@]}" shell getprop ro.product.cpu.abi | tr -d "\r")
case "$DEVICE_ABI" in
	x86_64)
		ARCH="android-x86_64"
		;;
	x86)
		ARCH="android-x86"
		;;
	arm64-v8a)
		ARCH="android-arm64"
		;;
	armeabi-v7a|armeabi)
		ARCH="android-arm"
		;;
	*)
		echo "[-] Unsupported Android ABI: $DEVICE_ABI"
		exit 1
		;;
esac
echo "[*] Device ABI: $DEVICE_ABI ($ARCH)"

FILENAME="frida-server-${FRIDA_VERSION}-${ARCH}.xz"
URL="https://github.com/frida/frida/releases/download/${FRIDA_VERSION}/${FILENAME}"
WORK_DIR="${FRIDA_WORK_DIR:-/tmp/mobile-security-engine-frida}"
mkdir -p "$WORK_DIR"

echo "[*] Fetching matched frida-server: $URL"
curl -L -o "$WORK_DIR/$FILENAME" "$URL"
xz -dkf "$WORK_DIR/$FILENAME"

UNCOMPRESSED="$WORK_DIR/frida-server-${FRIDA_VERSION}-${ARCH}"
"${ADB_CMD[@]}" root
"${ADB_CMD[@]}" wait-for-device
"${ADB_CMD[@]}" push "$UNCOMPRESSED" /data/local/tmp/frida-server
"${ADB_CMD[@]}" shell "chmod 755 /data/local/tmp/frida-server"
"${ADB_CMD[@]}" shell "killall frida-server >/dev/null 2>&1 || true"
"${ADB_CMD[@]}" shell "nohup /data/local/tmp/frida-server >/dev/null 2>&1 &"
sleep 3

"${ADB_CMD[@]}" shell "pidof frida-server >/dev/null || ps -A | grep frida-server >/dev/null"
"${ADB_CMD[@]}" forward tcp:27042 tcp:27042
echo "[+] Frida-Server initialized."
echo "[+] Forwarded local tcp:27042 to device tcp:27042."
