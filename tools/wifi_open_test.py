"""WiFi-only (cloud) open test: NO Bluetooth at all.

Usage:
    python tools\\wifi_open_test.py            # countdown, then fire openLock
    python tools\\wifi_open_test.py --watch    # auto-fire when lock wakes

Pure WiFi path, exactly what the HA integration does when no ESP32
Bluetooth proxy exists: login -> POST /v2/lock/openLock -> retry for a
window while the user wakes the lock (press 4 and # on the keypad, or
ring the bell) -> report.

Exit codes: 0 = openLock succeeded, 1 = lock never woke in the window,
2 = lock woke but openLock still failed (would be a real bug).
"""

from __future__ import annotations

import argparse
import asyncio
import json
import logging
import os
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))


def _load_env_file() -> None:
    envf = Path(__file__).resolve().parents[1] / ".env"
    if envf.is_file():
        for line in envf.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            k, _, v = line.partition("=")
            os.environ.setdefault(k.strip(), v.strip())


async def _openlock_once(client, device: str) -> None:
    body = await client._post("remote_unlock", {
        "id": device,
        "token": client.tokens.access_token,
        "timestamp": int(time.time() * 1000),
    })
    print(f"  [openLock] SUCCESS: {json.dumps(body)[:200]}")


async def run(device: str, wait_secs: int, watch: bool) -> int:
    from custom_components.fc_smarthome.api.client import FcClient
    from custom_components.fc_smarthome.api.endpoints import EndpointRegistry
    from custom_components.fc_smarthome.api.errors import FcError

    _load_env_file()
    region = os.environ.get("FC_REGION", "eu")
    registry = EndpointRegistry.load(region)
    client = FcClient(
        os.environ.get("FC_PHONE", ""),
        os.environ.get("FC_PASSWORD", ""),
        region,
        registry,
        country_code=os.environ.get("FC_CC", "34"),
    )
    await client.login()
    print(f"[login] OK (region={region}) — WiFi-only test, BLE disabled")

    if not watch:
        print()
        print("=" * 62)
        print("  WAKE THE LOCK NOW: press 4 then # on the keypad")
        print(f"  openLock fires in 10 seconds and retries for {wait_secs} s")
        print("=" * 62)
        for i in range(10, 0, -1):
            print(f"  {i}...")
            await asyncio.sleep(1)
    else:
        baseline = await client.get_history(device, limit=5)
        known = {e.timestamp.isoformat() for e in baseline if e.timestamp}
        print(f"[watch] {len(known)} recent events known; ring the bell /")
        print("  touch the keypad — openLock fires the moment a new event")
        print(f"  appears (max wait {wait_secs} s)")

    deadline = time.time() + wait_secs
    attempt = 0
    fired = False
    while time.time() < deadline:
        attempt += 1
        try:
            await _openlock_once(client, device)
            print(f"  [attempt {attempt}] openLock succeeded — "
                  "the WiFi/Wake theory is CONFIRMED end to end")
            await client.close()
            return 0
        except FcError as err:
            msg = str(err)
            fired = True
            if "682" in msg or "500" in msg:
                left = deadline - time.time()
                print(f"  [attempt {attempt}] lock asleep (HTTP 682) — "
                      f"retrying for {max(left, 0):.0f}s more "
                      "(press 4 + # / ring the bell)")
            else:
                print(f"  [attempt {attempt}] {msg[:130]}")
                await client.close()
                return 2
        if watch:
            try:
                events = await client.get_history(device, limit=5)
                fresh = [e for e in events
                         if e.timestamp and e.timestamp.isoformat() not in known]
                for e in fresh:
                    known.add(e.timestamp.isoformat())
                if fresh:
                    print(f"  [watch] wake event: {fresh[0].type.value} "
                          f"at {fresh[0].timestamp} — firing immediately")
            except FcError:
                pass
        await asyncio.sleep(3)

    await client.close()
    if fired:
        print("RESULT: lock never woke during the window. Check the lock's")
        print("WiFi (blue LED on / visible in the app) and try again.")
        return 1
    print("RESULT: no attempts ran.")
    return 1


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--device", default="7b120ba58284f360699d44cebaba0a12")
    parser.add_argument("--wait-secs", type=int, default=70,
                        help="retry window in seconds (default 70, "
                             "matching the HA integration's 60 s + margin)")
    parser.add_argument("--watch", action="store_true",
                        help="poll history and fire on the first new event "
                             "instead of a fixed 10 s countdown")
    parser.add_argument("--debug", action="store_true")
    args = parser.parse_args()
    logging.basicConfig(
        level=logging.DEBUG if args.debug else logging.WARNING,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )
    try:
        sys.exit(asyncio.run(run(args.device, args.wait_secs, args.watch)))
    except KeyboardInterrupt:
        sys.exit(130)


if __name__ == "__main__":
    main()
