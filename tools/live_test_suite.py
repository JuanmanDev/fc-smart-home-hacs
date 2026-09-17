"""Live test suite for the FC SmartHome integration (run against the real
cloud + real lock; user should be near the door).

    python tools/live_test_suite.py [--device DEV] [--skip-unlock]

Stages:
 1. login + device list + status          (cloud basics)
 2. full history + event type census      (history plumbing)
 3. battery statistics extraction preview (import_battery_stats data)
 4. users list                            (user plumbing)
 5. validateSecurityPassword + getLocalVerifyPassword (unlock prerequisites)
 6. remote unlock attempt                (expected to fail while lock
    sleeps — exit code tells which; run tools/unlock_awake_window.py to
    test the awake window with the bell)
 7. bell endpoint call                    (known: settings endpoint;
    degrades gracefully)

Prints a summary table at the end for copy/paste into the research notes.
"""
import argparse
import asyncio
import json
import logging
import os
import re
import sys
import time
from collections import Counter
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


RESULTS: list[tuple[str, str, str]] = []  # (stage, result, detail)


def record(stage: str, ok: bool, detail: str = "") -> None:
    RESULTS.append((stage, "PASS" if ok else "FAIL", detail))
    print(f"  [{stage}] {'PASS' if ok else 'FAIL'} {detail}")


async def run(device: str, skip_unlock: bool) -> None:
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
    now_ms = lambda: int(time.time() * 1000)

    # 1. cloud basics
    try:
        await client.login()
        devices = await client.get_devices()
        record("login+devices", True, f"{len(devices)} device(s): "
              + ", ".join(f"{d.name} ({d.battery}%)" if d.battery is not None else d.name
                          for d in devices))
    except FcError as err:
        record("login+devices", False, str(err)[:120])
        return

    try:
        status = await client.get_device_status(device)
        # prime _last_events so the relock window logic runs like in HA
        await client.get_history(device, limit=30)
        status = await client.get_device_status(device)
        record("status", True, f"locked={status.is_locked} battery={status.battery}% "
              f"door_open={status.door_open} child_lock={status.child_lock} "
              f"door_open_long={status.door_open_long} low_battery={status.low_battery}")
    except FcError as err:
        record("status", False, str(err)[:120])

    # 2. history
    try:
        events = await client.get_history(device, limit=0, from_ms=0)
        census = Counter(e.type.value for e in events)
        users = Counter(e.user for e in events if e.type.value == "unlocked" and e.user)
        record("history", True, f"{len(events)} events; types={dict(census)}; "
              f"unlock_users={dict(users)}")
    except FcError as err:
        record("history", False, str(err)[:120])
        events = []

    # 3. battery stats preview
    points = []
    for ev in events:
        if ev.timestamp and "battery" in (ev.description or "").lower():
            m = re.search(r"(\d{1,3})\s*%", ev.description or "")
            if m and 0 < int(m.group(1)) <= 100:
                points.append((ev.timestamp.timestamp(), int(m.group(1))))
    record("battery-stats", len(points) > 0,
           f"{len(points)} battery points "
           + (f"spanning {time.strftime('%Y-%m-%d', time.localtime(points[0][0]))}"
              f"..{time.strftime('%Y-%m-%d', time.localtime(points[-1][0]))}"
              if points else ""))

    # 4. users
    try:
        users = await client.get_users(device)
        record("users", True, f"{len(users)}: " + ", ".join(
            f"{u.name}({u.type.value})" for u in users[:10]))
    except FcError as err:
        record("users", False, str(err)[:120])

    # 5. unlock prerequisites
    try:
        b = await client._post("get_local_verify_password", {
            "id": device, "publicKey": "",
            "token": client.tokens.access_token, "timestamp": now_ms(),
        })
        record("getLocalVerifyPassword", True, f"data={str(b.get('data'))[:12]}...")
    except FcError as err:
        record("getLocalVerifyPassword", False, str(err)[:120])
    try:
        # security-password md5 from the environment (FC_SECURITY_MD5 in
        # .env) — never hardcode credentials in the repo
        sec_md5 = os.environ.get("FC_SECURITY_MD5", "")
        if not sec_md5:
            record("validateSecurityPassword", False, "skipped: FC_SECURITY_MD5 not set")
        else:
            await client._post("validate_security_password", {
                "password": sec_md5, "id": device,
                "token": client.tokens.access_token, "timestamp": now_ms(),
            })
            record("validateSecurityPassword", True, "static app md5 validates")
    except FcError as err:
        record("validateSecurityPassword", False, str(err)[:120])

    # 6. remote unlock (expected to fail while the lock sleeps)
    if not skip_unlock:
        try:
            body = await client._post("remote_unlock", {
                "id": device, "token": client.tokens.access_token,
                "timestamp": now_ms(),
            })
            record("openLock", True, f"UNLOCKED: {json.dumps(body)[:150]}")
        except FcError as err:
            record("openLock", False, str(err)[:120])

    # 7. bell (known settings endpoint)
    try:
        body = await client._post("bell", {
            "id": device, "token": client.tokens.access_token,
            "timestamp": now_ms(),
        })
        record("bell-endpoint", True, json.dumps(body)[:120])
    except FcError as err:
        record("bell-endpoint", False, f"expected: {str(err)[:100]}")

    await client.close()

    print()
    print("=" * 70)
    print(f"{'STAGE':34}{'RESULT':8}DETAIL")
    print("-" * 70)
    for stage, result, detail in RESULTS:
        print(f"{stage:34}{result:8}{detail[:90]}")
    print("=" * 70)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--device", default="7b120ba58284f360699d44cebaba0a12")
    parser.add_argument("--skip-unlock", action="store_true")
    parser.add_argument("--debug", action="store_true")
    args = parser.parse_args()
    logging.basicConfig(
        level=logging.DEBUG if args.debug else logging.WARNING,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )
    try:
        asyncio.run(run(args.device, args.skip_unlock))
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
