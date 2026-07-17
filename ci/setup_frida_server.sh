#!/bin/bash
# ci/setup_frida_server.sh
set -e

# Query runtime host version
FRIDA_VERSION=$(python3 -c "import frida; print(frida.__version__)")
echo "[*] Host Frida Version: $FRIDA_VERSION"

ARCH="android-x86_64" # Target for virtualized x86_64 emulator running on Linux host
FILENAME="frida-server-${FRIDA_VERSION}-${ARCH}.xz"
URL="https://github.com/frida/frida/releases/download/${FRIDA_VERSION}/${FILENAME}"

echo "[*] Fetching matched frida-server: $URL"
curl -L -o "$FILENAME" "$URL"
xz -d "$FILENAME"

UNCOMPRESSED="frida-server-${FRIDA_VERSION}-${ARCH}"
adb root
adb wait-for-device
adb push "$UNCOMPRESSED" /data/local/tmp/frida-server
adb shell "chmod 755 /data/local/tmp/frida-server"
adb shell "/data/local/tmp/frida-server &"
sleep 3

echo "[+] Frida-Server initialized."
