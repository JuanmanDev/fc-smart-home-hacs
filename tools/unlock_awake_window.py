"""Live test: remote unlock during the lock's awake window.

Usage:
    python tools/unlock_awake_window.py [--device DEV] [--wait-mins 15]

Watches the cloud history; the moment ANY new event appears (bell press,
fingerprint unlock, etc. — the lock is then awake and cloud-connected)
it fires /v2/lock/openLock within ~1-2 seconds. This is the decisive
test of the "WiFi lock sleeps; openLock only works while awake" theory
(see docs/RESEARCH-NOTES-2026-09-11.md).

Exit codes: 0 = unlocked successfully, 1 = window elapsed without events,
2 = openLock still failed during an awake window (theory wrong).
"""
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


async def run(device: str, wait_mins: float) -> int:
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

    await client.login()
    print(f"[login] OK (region={region})")

    baseline = await client.get_history(device, limit=5)
    known = {e.timestamp.isoformat() for e in baseline if e.timestamp}
    print(f"[baseline] {len(known)} recent events known")
    print()
    print("=" * 62)
    print("  WAKE THE LOCK NOW: press the bell button or turn the")
    print("  handle / touch the keypad, or open with your fingerprint.")
    print(f"  Watching for {wait_mins:.0f} minutes...")
    print("=" * 62)

    deadline = time.time() + wait_mins * 60
    saw_wake = False
    while time.time() < deadline:
        try:
            events = await client.get_history(device, limit=5)
        except FcError as err:
            print(f"  [poll error] {str(err)[:100]}")
            await asyncio.sleep(3)
            continue
        fresh = [e for e in events if e.timestamp and e.timestamp.isoformat() not in known]
        if fresh:
            for e in fresh:
                known.add(e.timestamp.isoformat())
            ev = fresh[0]
            print(f"[{time.strftime('%H:%M:%S')}] WAKE EVENT: {ev.type.value}"
                  f" at {ev.timestamp} user={ev.user or '-'}")
            if not saw_wake:
                saw_wake = True
                print("  -> lock is awake; firing openLock NOW")
            for attempt in range(5):
                try:
                    body = await client._post("remote_unlock", {
                        "id": device,
                        "token": client.tokens.access_token,
                        "timestamp": now_ms(),
                    })
                    print(f"  [openLock {attempt}] SUCCESS: {json.dumps(body)[:200]}")
                    print("*** IF THE DOOR OPENED, THE THEORY IS CONFIRMED ***")
                    await client.close()
                    return 0
                except FcError as err:
                    print(f"  [openLock {attempt}] {str(err)[:130]}")
                await asyncio.sleep(2)
        await asyncio.sleep(1.2)

    await client.close()
    if saw_wake:
        print("RESULT: lock woke up but openLock STILL failed -> sleep theory WRONG")
        return 2
    print("RESULT: no wake event seen during the window -> try again while "
          "pressing the bell. Check the lock has WiFi (blue LED / app settings).")
    return 1


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--device", default="7b120ba58284f360699d44cebaba0a12")
    parser.add_argument("--wait-mins", type=float, default=15.0)
    parser.add_argument("--debug", action="store_true")
    args = parser.parse_args()
    logging.basicConfig(
        level=logging.DEBUG if args.debug else logging.WARNING,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )
    try:
        sys.exit(asyncio.run(run(args.device, args.wait_mins)))
    except KeyboardInterrupt:
        sys.exit(130)


if __name__ == "__main__":
    main()
