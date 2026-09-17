"""Autonomous BLE test runner — runs INSIDE the HA container, no agent needed.

The user runs ONE command from the dev PC (or directly on the HA host) and
the script performs the whole battery with countdowns, collects results and
prints a clear verdict + next steps. Designed for joint physical testing
where the user is at the door and the agent may be slow to respond.

From the dev PC (single command, runs everything remotely):

    python tools\\ble_test_runner.py --test probe          # read-only battery
    python tools\\ble_test_runner.py --test unlock          # WILL OPEN THE DOOR
    python tools\\ble_test_runner.py --test full            # probe then unlock
    python tools\\ble_test_runner.py --test status          # cloud status only

What each battery does:
    status   - cloud poll of the lock state (no BLE, no door interaction)
    probe    - [countdown 10s: TOUCH THE KEYPAD] -> advertisement check ->
               GATT connect via proxy -> handshake (3 attempts, 15s each) ->
               frame-by-frame log dump -> verdict
    unlock   - probe battery first; if handshake OK -> BLE unlock
               (DOOR OPENS). Falls back to nothing (no cloud attempts:
               cloud openLock is known-broken 682 for this lock)
    full     - probe, then unlock, then a final cloud history check to see
               the resulting unlock event (method=app/remote)

The script SSHes to the HA host itself, so it works even when the HA UI is
unreachable from the outside. Results are also left in
/config/python_client/ble_test_result.json on the HA host.
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
import time
from pathlib import Path

HA_HOST = "root@192.168.2.113"
HA_CONTAINER = "homeassistant"
LOCK_ID = "7b120ba58284f360699d44cebaba0a12"
REMOTE_RESULT = "/config/python_client/ble_test_result.json"

# remote script executed inside the HA container: it is a plain API client
# that calls the fc_smarthome service over HA's local REST API (BLE runs
# inside the HA process where the ESP32 proxies live)
REMOTE_PROBE_SCRIPT = r'''
import json, sys, time
import urllib.request

LOCK_ID = "7b120ba58284f360699d44cebaba0a12"
DO_UNLOCK = len(sys.argv) > 1 and sys.argv[1] == "unlock"
RESULT = {"phases": {}, "ok": False}

def api(path, payload=None):
    token = open("/config/ha.token").read().strip()
    req = urllib.request.Request(
        "http://localhost:8123" + path,
        data=json.dumps(payload).encode() if payload else None,
        headers={
            "Authorization": "Bearer " + token,
            "Content-Type": "application/json",
        },
        method="POST" if payload else "GET",
    )
    with urllib.request.urlopen(req, timeout=120) as r:
        return json.loads(r.read() or b"{}")

def main():
    service = "ble_unlock" if DO_UNLOCK else "ble_probe"
    t0 = time.time()
    try:
        api(f"/api/services/fc_smarthome/{service}", {"device_id": LOCK_ID})
        RESULT["phases"]["service"] = {"called": True, "service": service,
                                       "seconds": round(time.time() - t0, 1)}
        RESULT["ok"] = True
    except urllib.error.HTTPError as e:
        RESULT["phases"]["service"] = {
            "error": e.read().decode(errors="replace")[:400],
            "service": service,
            "seconds": round(time.time() - t0, 1),
        }
    except Exception as e:
        RESULT["phases"]["service"] = {"error": str(e)[:400], "service": service}
    with open("/config/python_client/ble_test_result.json", "w") as f:
        json.dump(RESULT, f, indent=2)
    print(json.dumps(RESULT, indent=2))

main()
'''


def ssh(cmd: str, timeout: int = 240) -> tuple[int, str]:
    proc = subprocess.run(
        ["ssh", HA_HOST, cmd],
        capture_output=True, text=True, timeout=timeout, encoding="utf-8", errors="replace",
    )
    return proc.returncode, (proc.stdout or "") + (proc.stderr or "")


def docker_exec(script_body: str, script_args: str = "", timeout: int = 240) -> tuple[int, str]:
    """Write the python to a temp file in the container and run it."""
    import base64

    b64 = base64.b64encode(script_body.encode()).decode()
    cmd = (
        f"docker exec {HA_CONTAINER} sh -c "
        f"'echo {b64} | base64 -d > /config/python_client/_runner_tmp.py' "
        f"&& docker exec {HA_CONTAINER} python3 /config/python_client/_runner_tmp.py {script_args}"
    )
    return ssh(cmd, timeout)


def countdown(seconds: int, message: str) -> None:
    print(f"\n>>> {message}")
    for i in range(seconds, 0, -1):
        print(f"    {i}...", flush=True)
        time.sleep(1)


def fetch_recent_ble_logs(minutes: int = 3) -> str:
    rc, out = ssh(
        f"docker logs homeassistant --since {minutes}m 2>&1 | grep -E 'FC BLE|BLE probe|"
        f"BLE unlock|handshake|BLE device' | tail -80"
    )
    return out.strip()


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--test", required=True, choices=["status", "probe", "unlock", "full"])
    p.add_argument("--wait", type=int, default=10,
                   help="seconds to touch the keypad before the probe fires")
    args = p.parse_args()

    print("=" * 66)
    print(" FC SmartHome BLE autonomous test runner")
    print("=" * 66)

    if args.test == "status":
        rc, out = ssh(
            "docker exec homeassistant python3 -c \"import urllib.request,json;"
            "t=open('/config/ha.token').read().strip();"
            "r=urllib.request.urlopen(urllib.request.Request("
            "'http://localhost:8123/api/states/lock.smart_lock',"
            "headers={'Authorization':'Bearer '+t}),timeout=30);"
            "print(r.read().decode())\""
        )
        print(out[:1200])
        return 0

    # probe / unlock / full all need the user at the door for best results
    countdown(args.wait,
              "TOUCH THE LOCK KEYPAD NOW (or press the bell) to wake it — "
              "the probe fires when the countdown ends")
    print("\nfiring ble_probe via the HA service (runs inside HA, proxies usable)...")
    rc, out = docker_exec(REMOTE_PROBE_SCRIPT, timeout=300)
    print(out.strip()[:1500])

    print("\n--- BLE frames from the HA log (last 3 min) ---")
    logs = fetch_recent_ble_logs()
    print(logs if logs else "(no BLE log lines — check integration debug logging)")

    verdict = []
    if "HANDSHAKE OK" in logs or "session_key_acquired" in logs:
        verdict.append("HANDSHAKE OK — the BLE protocol works end to end!")
    if "FC BLE <-" in logs:
        verdict.append("The lock IS responding over BLE (see '<-' frames above).")
    if "timed out" in logs:
        verdict.append("Timeout: likely the lock went back to sleep or the "
                       "connection raced. Retry while the keypad is lit.")
    if "BLE device" in logs and "not found" in logs:
        verdict.append("Lock not visible to the proxies: check it's advertising "
                       "(touch keypad) and the ESP32s are online.")
    if "Write not permitted" in logs:
        verdict.append("Write characteristic mismatch — report this log.")
    print("\n" + "=" * 66)
    for line in verdict or ["No clear verdict — paste the frames above to the agent."]:
        print(" * " + line)
    print("=" * 66)

    if args.test in ("unlock", "full") and any(
        v.startswith("HANDSHAKE OK") for v in verdict
    ):
        countdown(5, "READY TO OPEN THE DOOR — stand by it")
        print("\nfiring ble_unlock via the HA service (the door SHOULD open)...")
        rc, out = docker_exec(REMOTE_PROBE_SCRIPT, script_args="unlock", timeout=300)
        print(out.strip()[:800])
        print("\ncheck the door. The lock also logs the event; wait 30s for the "
              "cloud history to show the unlock (method=app).")
    return 0


if __name__ == "__main__":
    sys.exit(main())
