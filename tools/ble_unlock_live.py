"""LIVE test: FC lock over BLE via the ESP32 Bluetooth proxies.

Two run modes:

A) Inside the HA container (proxies via our standalone bridge â€” no HA
   manager needed, works with docker exec):

     # from the dev PC:
     scp -r fcble root@192.168.2.113:/docker/homeassistant/python_client/
     scp tools/ble_unlock_live.py root@192.168.2.113:/docker/homeassistant/python_client/
     ssh root@192.168.2.113
     docker exec -it homeassistant python3 /config/python_client/ble_unlock_live.py --phase scan

B) On any machine with its own BT adapter (e.g. laptop next to the door):

     python tools/ble_unlock_live.py --phase scan --local

PHASES (run in order; each is safe to repeat):
    scan      - list FC locks visible via the proxies (read-only)
    connect   - GATT connect + enumerate services (read-only)
    handshake - connect + VERIFY_IDENTITY handshake (returns session key,
                model/firmware; wakes the keypad; NO unlock)
    open      - handshake + REMOTE UNLOCK (door OPENS!)
    openid N  - handshake + unlock credited to user id N (default 12)

Env/args:
    --mac 34:17:27:05:19:20    lock BLE MAC (default known)
    --lockid 7b12...            cloud lock id (deviceuuid)
    --key 4CAD...               bluetoothKey (32 hex chars)
    --wait SECONDS              stay connected in 'connect' phase
    --proxy living-cover|kitchen   force a specific proxy
    --local                     use the machine's own BT adapter
"""

from __future__ import annotations

import argparse
import asyncio
import os
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from fcble import DEFAULT_BLE_KEY, FC_SERVICE_UUID
from fcble.client import FcBleLockClient

LOCK_MAC = os.environ.get("FC_LOCK_MAC", "34:17:27:05:19:20")
LOCK_ID = os.environ.get("FC_LOCK_ID", "7b120ba58284f360699d44cebaba0a12")


async def _proxy_bridge():
    from fcble.esphome_bridge import MultiProxyBLE, setup_standalone_bluetooth
    await setup_standalone_bluetooth()
    return MultiProxyBLE()


async def phase_scan(args) -> int:
    print("== PHASE scan: looking for the L5 lock ==")
    if args.local:
        from fcble.client import scan_locks
        locks = await scan_locks(timeout=12.0)
        if not locks:
            print("no FC locks found with the local adapter")
            return 1
        for lck in locks:
            print(f"  {lck['address']}  name={lck['name']!r} rssi={lck['rssi']}dBm")
        return 0

    mp = await _proxy_bridge()
    names = await mp.start()
    if not names:
        print("no proxies connected (are the ESP32s online?)")
        return 1
    print(f"proxies online: {names}\n")
    # give the scanners a few seconds to accumulate advertisements
    for round_ in range(6):
        await asyncio.sleep(2)
        for name in names:
            b = next(x for x in mp.bridges if x.name == name)
            hits = []
            for addr, (dev, adv) in b.seen_devices.items():
                nm = (dev.name or adv.local_name or "")
                if "L5" in (nm or "").upper() or "34:17:27" in addr.upper():
                    hits.append((addr, nm, adv.rssi))
            if hits:
                for addr, nm, rssi in hits:
                    print(f"  [{b.name}] {addr} name={nm!r} rssi={rssi}dBm")
            else:
                print(f"  [{b.name}] no L5 yet ({round_ * 2}s)...")
        found = mp.find_lock(LOCK_MAC)
        if found:
            print(f"\n>>> LOCK SEEN via {found[0].name} at {found[1]}dBm")
            if found[1] < -95:
                print("    (weak signal; unlock may still work - BLE connect is tolerant)")
            await mp.stop()
            return 0
    print("\nlock not seen in 12s: touch the keypad / press the bell to wake it, then rerun")
    await mp.stop()
    return 1


async def _open_client(args):
    """Return a connected FcBleLockClient via proxy or local adapter."""
    if args.local:
        client = FcBleLockClient(args.mac, args.lockid, args.key)
        await client.connect()
        return client, None

    mp = await _proxy_bridge()
    names = [args.proxy] if args.proxy else None
    ok = await mp.start(names)
    if not ok:
        raise RuntimeError(f"no proxies connected (tried {names or 'all'})")
    best = None
    for _ in range(6):
        await asyncio.sleep(2)
        best = mp.find_lock(args.mac)
        if best:
            break
    if not best:
        await mp.stop()
        raise RuntimeError("lock not seen by any proxy - wake it (bell/keypad) and rerun")
    bridge, rssi = best
    print(f"using proxy {bridge.name} (rssi {rssi}dBm)")
    from fcble.client import FcBleLockClient
    # build a client whose transport goes through this proxy
    client = ProxyFcBleLockClient(bridge, args.mac, args.lockid, args.key)
    await client.connect()
    return client, mp


class ProxyFcBleLockClient(FcBleLockClient):
    """FcBleLockClient whose bleak client is the ESPHome proxy one."""

    def __init__(self, bridge, address, lock_id, key):
        super().__init__(address, lock_id, key)
        self._bridge = bridge

    async def connect(self, timeout: float = 15.0) -> bool:
        from bleak_esphome.backend.client import ESPHomeClient
        self._client = await self._bridge.gatt_connect(self.address)
        from fcble import FC_NOTIFY_CHAR_UUID
        from fcble import FcBleFrameParser
        await self._client.start_notify(FC_NOTIFY_CHAR_UUID, self._on_notify)
        self._parser = FcBleFrameParser(self.initial_key)
        self._index = 1
        self._session_key = None
        return True


async def phase_connect(args) -> int:
    print("== PHASE connect: GATT connect + service enumeration (read-only) ==")
    client, mp = await _open_client(args)
    print("connected via proxy!")
    services = client._client.services
    found_fc = False
    for svc in services:
        print(f"  service {svc.uuid}")
        for ch in svc.characteristics:
            flags = ",".join(ch.properties)
            print(f"    char {ch.uuid} [{flags}]")
            if "ffe0" in svc.uuid.lower():
                found_fc = True
    if not found_fc:
        print(f"WARNING: service {FC_SERVICE_UUID} missing from GATT table")
    print(f"\nstaying connected {args.wait}s (the keypad usually wakes on connect)")
    for i in range(args.wait, 0, -1):
        print(f"  {i:3d}s", flush=True)
        await asyncio.sleep(1)
    await client.disconnect()
    if mp:
        await mp.stop()
    print("disconnected cleanly")
    return 0


async def phase_handshake(args) -> int:
    print("== PHASE handshake: VERIFY_IDENTITY (NO unlock) ==")
    client, mp = await _open_client(args)
    try:
        info = await client.handshake(timeout=12.0)
    except Exception as err:  # noqa: BLE001
        print(f"handshake FAILED: {type(err).__name__}: {err}")
        await client.disconnect()
        if mp:
            await mp.stop()
        return 1
    print("HANDSHAKE OK:")
    for k, v in info.items():
        print(f"  {k}: {v}")
    print(">>> if the info looks sane, next: --phase open")
    await client.disconnect()
    if mp:
        await mp.stop()
    return 0


async def phase_open(args, with_id: int | None) -> int:
    print("== PHASE open: REMOTE UNLOCK â€” THE DOOR WILL OPEN ==")
    if not args.yes:
        ok = input("type YES to open the door now: ").strip()
        if ok != "YES":
            print("aborted")
            return 1
    client, mp = await _open_client(args)
    try:
        info = await client.handshake(timeout=12.0)
        print(f"handshake ok (model={info.get('model')} fw={info.get('firmware')})")
        t0 = time.time()
        if with_id is None:
            res = await client.open(timeout=15.0)
        else:
            res = await client.open_with_id(with_id, timeout=15.0)
        dt = (time.time() - t0) * 1000
        print(f"open result: {res} ({dt:.0f} ms)")
        if res.get("ok"):
            print("\n*** THE DOOR OPENED VIA BLE THROUGH THE ESP32 PROXIES ***")
            return 0
        print(f"\nopen failed result={res.get('result')} (see fcble error codes)")
        return 1
    finally:
        await client.disconnect()
        if mp:
            await mp.stop()


def main() -> int:
    p = argparse.ArgumentParser()
    p.add_argument("--phase", required=True,
                   choices=["scan", "connect", "handshake", "open", "openid"])
    p.add_argument("--mac", default=LOCK_MAC)
    p.add_argument("--lockid", default=LOCK_ID)
    p.add_argument("--key", default=os.environ.get("FC_BLE_KEY", DEFAULT_BLE_KEY))
    p.add_argument("--wait", type=int, default=20)
    p.add_argument("--proxy", choices=["living-cover", "kitchen"])
    p.add_argument("--local", action="store_true",
                   help="use this machine's BT adapter instead of proxies")
    p.add_argument("--yes", action="store_true")
    args = p.parse_args()

    if args.phase == "scan":
        return asyncio.run(phase_scan(args))
    if args.phase == "connect":
        return asyncio.run(phase_connect(args))
    if args.phase == "handshake":
        return asyncio.run(phase_handshake(args))
    if args.phase == "open":
        return asyncio.run(phase_open(args, None))
    if args.phase == "openid":
        return asyncio.run(phase_open(args, 12))  # Juanma 220993
    return 1


if __name__ == "__main__":
    sys.exit(main())
