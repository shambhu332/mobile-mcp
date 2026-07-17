# ci/run_pipeline_hooks.py
import frida
import sys
import time

PACKAGE_NAME = "com.example.app"
test_passed = False

def handle_pipeline_messages(message, data):
    global test_passed
    if message['type'] == 'send':
        payload = message['payload']
        if payload.get("type") == "SECURITY_CHECK_STATUS":
            test_passed = payload.get("is_safe")

def run_pipeline_audit():
    global test_passed
    device = frida.get_usb_device()
    pid = device.spawn([PACKAGE_NAME])
    session = device.attach(pid)
    
    script = session.create_script("""
        Java.perform(function() {
            var Security = Java.use("com.example.app.Security");
            Security.evaluateDeviceState.implementation = function() {
                var res = this.evaluateDeviceState();
                send({ type: "SECURITY_CHECK_STATUS", is_safe: res });
                return res;
            }
        });
    """)
    script.on('message', handle_pipeline_messages)
    script.load()
    device.resume(pid)
    
    # Wait for execution context verification (Timeout after 10s)
    time.sleep(10)
    session.detach()
    
    if test_passed:
        print("[+] CI Test Passed: Runtime security policies satisfied.")
        sys.exit(0)
    else:
        print("[-] CI Test Failed: Security verification failed.")
        sys.exit(1)

if __name__ == "__main__":
    run_pipeline_audit()
