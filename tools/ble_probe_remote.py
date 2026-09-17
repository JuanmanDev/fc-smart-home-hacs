"""Deploy the BLE probe/unlock from the dev PC: calls the HA service via SSH.

Usage (user at the door):
    python tools\ble_probe_remote.py probe     # read-only handshake test
    python tools\ble_probe_remote.py unlock    # WILL OPEN THE DOOR

Run this, then TOUCH THE LOCK KEYPAD (press 4 then #) when the countdown
shows. The probe fires when it hits 0.
"""

from __future__ import annotations

import base64
import subprocess
import sys
import time

HA_HOST = "root@192.168.2.113"
LOCK_ID = "7b120ba58284f360699d44cebaba0a12"

REMOTE = r'''
import json, sys, time, urllib.request
LOCK_ID = "7b120ba58284f360699d44cebaba0a12"
DO_UNLOCK = len(sys.argv) > 1 and sys.argv[1] == "unlock"

def api(path, payload=None):
    token = open("/config/ha.token").read().strip()
    req = urllib.request.Request(
        "http://localhost:8123" + path,
        data=json.dumps(payload).encode() if payload else None,
        headers={"Authorization": "Bearer " + token,
                 "Content-Type": "application/json"},
        method="POST" if payload else "GET")
    with urllib.request.urlopen(req, timeout=180) as r:
        return json.loads(r.read() or b"{}")

t0 = time.time()
service = "ble_unlock" if DO_UNLOCK else "ble_probe"
try:
    api(f"/api/services/fc_smarthome/{service}", {"device_id": LOCK_ID})
    print(json.dumps({"ok": True, "service": service,
                      "seconds": round(time.time() - t0, 1)}))
except urllib.error.HTTPError as e:
    print(json.dumps({"ok": False, "service": service,
                      "error": e.read().decode(errors="replace")[:500]}))
except Exception as e:
    print(json.dumps({"ok": False, "service": service, "error": str(e)[:500]}))
'''


def ssh_docker_exec(script: str, arg: str, timeout: int = 300) -> str:
    b64 = base64.b64encode(script.encode()).decode()
    cmd = (
        f'docker exec homeassistant sh -c "echo {b64} | base64 -d > /config/python_client/_probe.py" '
        f'&& docker exec homeassistant python3 /config/python_client/_probe.py {arg}'
    )
    proc = subprocess.run(["ssh", HA_HOST, cmd], capture_output=True,
                          text=True, timeout=timeout, encoding="utf-8",
                          errors="replace")
    return (proc.stdout or "") + (proc.stderr or "")


def fetch_logs(minutes: int = 3) -> str:
    proc = subprocess.run(
        ["ssh", HA_HOST,
         f"docker logs homeassistant --since {minutes}m 2>&1 | grep -E 'FC BLE|BLE probe|handshake|GATT|identity' | tail -60"],
        capture_output=True, text=True, timeout=120, encoding="utf-8",
        errors="replace",
    )
    return (proc.stdout or "").strip()


def countdown(seconds: int, msg: str) -> None:
    print(f"\n>>> {msg}")
    for i in range(seconds, 0, -1):
        print(f"    {i}...", flush=True)
        time.sleep(1)


def main() -> int:
    mode = sys.argv[1] if len(sys.argv) > 1 else "probe"
    print("=" * 66)
    print(" FC SmartHome BLE remote probe (fixed protocol: no heart prime,")
    print(" deviceuuid identity, v1/v2 auto-detect, seq sync)")
    print("=" * 66)
    countdown(
        15,
        "TOUCH THE KEYPAD NOW: press 4 then # (wake mode, 1 min window). "
        "The probe fires when the countdown ends.",
    )
    print(f"\nfiring ble_{mode} ...")
    out = ssh_docker_exec(REMOTE, mode)
    print(out.strip()[:800])

    print("\n--- BLE frames from the HA log (last 3 min) ---")
    logs = fetch_logs()
    print(logs if logs else "(none)")

    print("\n" + "=" * 66)
    if "FC BLE <-" in logs:
        print(" * THE LOCK IS RESPONDING! See '<-' frames above.")
    if "handshake" in logs and "OK" in logs:
        print(" * HANDSHAKE OK — protocol fixed!")
    if "timed out" in logs:
        print(" * Still timing out — paste frames above for analysis.")
    print("=" * 66)
    return 0


if __name__ == "__main__":
    sys.exit(main())
