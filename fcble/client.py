"""Async FC BLE client over bleak.

Works with any bleak backend:
- local adapter (Windows/Linux with a BT dongle) — best for bench tests
- ESPHome Bluetooth proxies inside the Home Assistant container
  (bleak-esphome), when run there with the HA bluetooth manager active.
"""

from __future__ import annotations

import asyncio
import logging
from typing import Callable, Optional

from bleak import BleakClient, BleakScanner
from bleak.backends.characteristic import BleakGATTCharacteristic
from bleak.exc import BleakError

from . import (
    CMD_SPECIAL_HEART,
    CMD_SYSTEM_VERIFY_IDENTITY,
    DEFAULT_BLE_KEY,
    FC_NOTIFY_CHAR_UUID,
    FC_SERVICE_UUID,
    FC_WRITE_CHAR_UUID,
    FcBleFrameParser,
    FcBleMessage,
    make_handshake,
    make_heartbeat,
    make_open,
    make_open_with_id,
    parse_handshake_response,
)

_LOGGER = logging.getLogger(__name__)

NOTIFY_TIMEOUT = 8.0
CONNECT_TIMEOUT = 12.0


class FcBleLockClient:
    """High-level client for one FC lock."""

    def __init__(self, address: str, lock_id: str,
                 key: str = DEFAULT_BLE_KEY, name_substring: str = "L5"):
        self.address = address
        self.lock_id = lock_id
        self.initial_key = key
        self.name_substring = name_substring
        self._index = 1
        self._session_key: Optional[str] = None
        self._parser: Optional[FcBleFrameParser] = None
        self._client: Optional[BleakClient] = None
        self._pending: dict[int, asyncio.Future] = {}
        self._notify_cb: Optional[Callable[[FcBleMessage], None]] = None
        self.device_info: dict = {}

    @property
    def active_key(self) -> str:
        """Key for the current link (session key after handshake)."""
        return self._session_key or self.initial_key

    # ---------- discovery ----------

    async def find_address(self, timeout: float = 10.0) -> Optional[str]:
        """Scan and return the lock's address (cached self.address if set)."""
        if self.address:
            return self.address
        dev = await BleakScanner.find_device_by_filter(
            lambda d, ad: (
                (d.name and self.name_substring.lower() in d.name.lower())
                or FC_SERVICE_UUID.lower() in [s.lower() for s in (ad.service_uuids or [])]
            ),
            timeout=timeout,
        )
        return dev.address if dev else None

    # ---------- connection ----------

    async def connect(self, timeout: float = CONNECT_TIMEOUT) -> bool:
        addr = await self.find_address()
        if not addr:
            raise BleakError(f"lock not found (name~'{self.name_substring}')")
        self.address = addr
        self._client = BleakClient(addr)
        await asyncio.wait_for(self._client.connect(), timeout)
        await self._client.start_notify(FC_NOTIFY_CHAR_UUID, self._on_notify)
        self._parser = FcBleFrameParser(self.initial_key)
        self._index = 1
        self._session_key = None
        return True

    async def disconnect(self) -> None:
        if self._client and self._client.is_connected:
            try:
                await self._client.stop_notify(FC_NOTIFY_CHAR_UUID)
            except Exception:  # noqa: BLE001
                pass
            await self._client.disconnect()
        self._client = None

    @property
    def is_connected(self) -> bool:
        return bool(self._client and self._client.is_connected)

    # ---------- transport ----------

    def _on_notify(self, _char: BleakGATTCharacteristic, data: bytearray) -> None:
        if self._parser is None:
            return
        if self._session_key:
            self._parser.key = self._session_key
        for msg, _pid in self._parser.feed(bytes(data)):
            fut = self._pending.pop(msg.cmd, None) or self._pending.pop(-1, None)
            if fut and not fut.done():
                fut.set_result(msg)
            if self._notify_cb:
                try:
                    self._notify_cb(msg)
                except Exception:  # noqa: BLE001
                    _LOGGER.exception("notify callback failed")

    async def _write(self, msg: FcBleMessage) -> None:
        frame = msg.to_frame(self.active_key)
        _LOGGER.debug("BLE -> %s", frame.hex())
        # the app writes in <=20-byte chunks (O=20); bigger single writes
        # can be silently dropped by the lock
        for i in range(0, len(frame), 20):
            await self._client.write_gatt_char(
                FC_WRITE_CHAR_UUID, frame[i:i + 20], response=False
            )

    async def _request(self, msg: FcBleMessage, timeout: float = NOTIFY_TIMEOUT) -> FcBleMessage:
        fut: asyncio.Future = asyncio.get_running_loop().create_future()
        self._pending[msg.cmd] = fut
        self._pending[-1] = fut  # fallback slot
        await self._write(msg)
        try:
            return await asyncio.wait_for(fut, timeout)
        finally:
            self._pending.pop(msg.cmd, None)
            self._pending.pop(-1, None)

    def _next_index(self) -> int:
        idx = self._index
        self._index += 1
        return idx

    # ---------- protocol ----------

    async def handshake(self, timeout: float = NOTIFY_TIMEOUT) -> dict:
        """VERIFY_IDENTITY handshake; returns device info (and stores the
        per-session AES key)."""
        msg = make_handshake(self.lock_id, index=self._next_index())
        resp = await self._request(msg, timeout)
        if resp.cmd_category == 240 and resp.cmd == 241:
            raise BleakError(f"lock rejected handshake: {resp.data.hex()}")
        info = parse_handshake_response(resp.data)
        if info.get("result") not in (0, 241):
            raise BleakError(f"handshake failed, result={info.get('result')} "
                             f"data={resp.data.hex()}")
        self.device_info = info
        key = info.get("aeskey")
        if key and len(key) == 32:
            self._session_key = key
            if self._parser:
                self._parser.key = key
        return info

    async def open(self, timeout: float = 10.0) -> dict:
        """Remote unlock (cat 4 cmd 16)."""
        msg = make_open(index=self._next_index())
        resp = await self._request(msg, timeout)
        result = resp.data[0] if resp.data else None
        return {"result": result, "ok": result in (0, 241)}

    async def open_with_id(self, user_id: int, timeout: float = 10.0) -> dict:
        """Unlock credited to userId (cat 4 cmd 24)."""
        msg = make_open_with_id(self._next_index(), user_id)
        resp = await self._request(msg, timeout)
        result = resp.data[0] if resp.data else None
        return {"result": result, "ok": result in (0, 241)}

    async def heartbeat(self) -> None:
        msg = make_heartbeat(self._next_index())
        await self._write(msg)

    async def unlock(self, user_id: int | None = None) -> dict:
        """Full flow: connect -> handshake -> open -> disconnect."""
        try:
            await self.connect()
            info = await self.handshake()
            _LOGGER.info("handshake ok: model=%s fw=%s mac=%s",
                         info.get("model"), info.get("firmware"), info.get("mac"))
            if user_id is not None:
                return await self.open_with_id(user_id)
            return await self.open()
        finally:
            await self.disconnect()


async def scan_locks(timeout: float = 10.0) -> list[dict]:
    """Scan for FC locks advertising the 01fa service; returns dicts."""
    devices = await BleakScanner.discover(timeout=timeout, return_adv=True)
    found = []
    for d, adv in devices.values():
        uuids = [str(u).lower() for u in (adv.service_uuids or [])]
        name = d.name or (adv.local_name or "")
        if "l5" in name.lower() or "000001fa" in "".join(uuids):
            found.append({
                "address": d.address,
                "name": name,
                "rssi": adv.rssi,
                "uuids": uuids,
            })
    return sorted(found, key=lambda x: -(x["rssi"] or -999))
