"""Continuous BLE probe loop — keeps trying connect+handshake for minutes.

Each round:
  1. wait for a fresh advertisement of the lock (HA bluetooth callback)
  2. GATT connect via the best proxy
  3. send the VERIFY_IDENTITY handshake (chunked 20B writes)
  4. report everything; never unlocks

Run: python tools/ble_probe_loop.py --minutes 10
     (from the dev PC it uses --local; inside HA use the service instead)
"""

from __future__ import annotations

import argparse
import asyncio
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from fcble import DEFAULT_BLE_KEY
from fcble.client import FcBleLockClient

LOCK_MAC = "34:17:27:05:19:20"
LOCK_ID = "7b120ba58284f360699d44cebaba0a12"


async def main() -> int:
    p = argparse.ArgumentParser()
    p.add_argument("--minutes", type=float, default=10.0)
    p.add_argument("--mac", default=LOCK_MAC)
    p.add_argument("--lockid", default=LOCK_ID)
    p.add_argument("--key", default=DEFAULT_BLE_KEY)
    p.add_argument("--local", action="store_true",
                   help="use this machine's BT adapter")
    args = p.parse_args()

    deadline = time.time() + args.minutes * 60
    attempt = 0
    while time.time() < deadline:
        attempt += 1
        print(f"\n=== attempt {attempt} @ {time.strftime('%H:%M:%S')} ===")
        client = FcBleLockClient(args.mac, args.lockid, args.key)
        try:
            addr = await client.find_address(timeout=15.0)
            if not addr:
                print("  no advertisement; wake the lock (bell/keypad) and keep watching")
                await asyncio.sleep(5)
                continue
            print(f"  advertisement seen, connecting GATT...")
            await asyncio.wait_for(client.connect(), timeout=25.0)
            print("  connected! sending handshake (chunked 20B writes)...")
            info = await client.handshake(timeout=15.0)
            print("  HANDSHAKE OK:")
            for k, v in info.items():
                print(f"    {k}: {v}")
            await client.disconnect()
            print("\n>>> SUCCESS — the BLE channel works. Next: BLE unlock service.")
            return 0
        except Exception as err:  # noqa: BLE001
            print(f"  attempt failed: {type(err).__name__}: {err}")
            try:
                await client.disconnect()
            except Exception:  # noqa: BLE001
                pass
        await asyncio.sleep(8)
    print("\nloop finished without a successful handshake")
    return 1


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
