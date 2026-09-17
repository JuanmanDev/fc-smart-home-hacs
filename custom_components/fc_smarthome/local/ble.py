"""Local Bluetooth Low Energy transport for FC SmartHome devices.

Fingerchip locks pair over BLE. This module provides:
- scanning by name prefix / advertised service UUID
- pairing handshake (magic header + rolling token)
- local command channel: lock/unlock/latch/beep, read devStatus
- local event subscription via notifications

Frame layout is the hypothesis from sibling Alibaba-style lock BLE firmwares
(4-byte magic 'FCFC', length, command, payload, checksum). It MUST be verified
with a btsnoop/HCI capture of the official app (tools/HARVEST.md).
"""

from __future__ import annotations

import asyncio
import contextlib
import json
import logging
import random
import struct
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable

from ..api.const import DEVICE_STATUS_MASKS
from ..api.errors import FcLocalError
from ..api.models import LockStatus

_LOGGER = logging.getLogger(__name__)

BLE_IMPORT_ERROR = None
try:
    from bleak import BleakClient, BleakScanner
    from bleak.backends.device import BLEDevice
    from bleak.backends.characteristic import BleakGATTCharacteristic
except ImportError as err:  # pragma: no cover - optional runtime dependency
    BLE_IMPORT_ERROR = str(err)

try:
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    from cryptography.hazmat.backends import default_backend
except ImportError:  # pragma: no cover
    Cipher = None

MAGIC = b"FCFC"

# Official FC SmartHome Bluetooth LE GATT UUIDs (extracted from Lock_Controller)
DEFAULT_AES_KEY = "4CADB87095639211A1303639D98E9150"
SCAN_FILTER_UUID = "000001fa-0000-1000-8000-00805f9b34fb"
SERVICE_UUID = "0000ffe0-0000-1000-8000-00805f9b34fb"
CHAR_UUID = "0000ffe1-0000-1000-8000-00805f9b34fb"

# FCBle Command Categories
CATEGORY_SYSTEM = 0x02
CATEGORY_USER = 0x04
CATEGORY_RECORD = 0x08
CATEGORY_WARN = 0x10
CATEGORY_SPECIAL = 0xF0

# FCBle OpCodes
CMD_SYSTEM_BIND = 0x01
CMD_SYSTEM_SET_LOCK_PARAM = 0x06
CMD_SYSTEM_VERIFY_IDENTITY = 0x08
CMD_USER_QUERY_IDS = 0x01
CMD_USER_REMOTE_UNLOCK = 0x10
CMD_USER_READ_RECORD = 0x12
CMD_USER_ID_BLE_OPEN = 0x18


def ble_encrypt(plaintext: bytes, key_hex: str = DEFAULT_AES_KEY) -> bytes:
    """AES-128-ECB NoPadding encryption with zero-padding (matching app module 0fd2)."""
    if Cipher is None:
        raise FcLocalError("cryptography library is required for FC BLE encryption")
    pad_len = (16 - (len(plaintext) % 16)) % 16
    padded = plaintext + b"\x00" * pad_len
    key = bytes.fromhex(key_hex)
    cipher = Cipher(algorithms.AES(key), modes.ECB(), backend=default_backend())
    enc = cipher.encryptor()
    return enc.update(padded) + enc.finalize()


def ble_decrypt(ciphertext: bytes, key_hex: str = DEFAULT_AES_KEY) -> bytes:
    """AES-128-ECB NoPadding decryption (matching app module 0fd2)."""
    if Cipher is None:
        raise FcLocalError("cryptography library is required for FC BLE decryption")
    key = bytes.fromhex(key_hex)
    cipher = Cipher(algorithms.AES(key), modes.ECB(), backend=default_backend())
    dec = cipher.decryptor()
    return dec.update(ciphertext) + dec.finalize()


def calc_checksum(pid: int, length: int, payload: bytes) -> int:
    """Frame checksum: pid ^ len_low ^ len_high ^ payload bytes (module 4048)."""
    len_low = length % 256
    len_high = length // 256
    chk = pid ^ len_low ^ len_high
    for b in payload:
        chk ^= b
    return chk


# Golden vendor frame captured inside the app bundle (module 65eb `he()`):
# the loss-prevention "heart" the app writes with cmd 0x30 cat 0xF0, pid 0xFF.
GOLDEN_HEART_FRAME = bytes.fromhex(
    "FDFF1600088AAF3DC1ABE8D57CCBB83CAE35C2AF6BFE"
)


def _normalize(address: str) -> str:
    """Normalize a MAC to colon format (cloud uses raw hex)."""
    raw = address.strip().replace(":", "").replace("-", "").upper()
    if len(raw) == 12:
        return ":".join(raw[i:i + 2] for i in range(0, 12, 2))
    return address


@dataclass
class FCBleBaseMessage:
    """Inner BLE message structure (matching app module 45cc)."""
    cmd_category: int
    cmd: int
    data: bytes = b""
    seq: int = 1
    pid: int = 0

    def encode(self, version: int = 2) -> bytes:
        """Inner plaintext bytes (module 45cc getBytes(version)).

        v2: len(=9+data, xor byte counted) + index LE32 + cat + cmd + data + xor
        v1: same layout WITHOUT the trailing xor byte and the length field
            counts only 8 header bytes + data (getBytes: a=this.length-1,
            lenArray(a) — so len = data+8, one less than v2).
        """
        data_len = len(self.data)
        if version == 2:
            msg_len = data_len + 9
            xor = self._data_xor(msg_len)
            return (
                struct.pack("<H", msg_len)
                + struct.pack("<I", self.seq)
                + bytes([self.cmd_category, self.cmd])
                + self.data
                + bytes([xor])
            )
        msg_len = data_len + 8  # v1: no xor byte in the count
        return (
            struct.pack("<H", msg_len)
            + struct.pack("<I", self.seq)
            + bytes([self.cmd_category, self.cmd])
            + self.data
        )

    def _data_xor(self, msg_len: int | None = None) -> int:
        """XOR of lenLo^lenHi^cat^cmd^data (module 45cc makeData_xor)."""
        n = msg_len if msg_len is not None else len(self.data) + 9
        xor = (n % 256) ^ (n // 256) ^ self.cmd_category ^ self.cmd
        for b in self.data:
            xor ^= b
        return xor & 0xFF

    @classmethod
    def decode(cls, data: bytes, pid: int = 0, version: int = 2) -> "FCBleBaseMessage | None":
        """Parse a decrypted inner message (module 45cc fromBytes).

        v2: length counts the xor byte (s=9); data runs to length-1.
        v1: s=8; data runs to length-8 (to the end of the message).
        """
        if len(data) < 8:
            return None
        msg_len = data[0] | (data[1] << 8)
        seq = struct.unpack_from("<I", data, 2)[0]
        cmd_cat = data[6]
        cmd = data[7]
        if version == 2:
            if len(data) < msg_len or msg_len < 9:
                return None
            payload = data[8:msg_len - 1]
        else:
            if msg_len < 8:
                return None
            # v1: len counts header+data only (no xor); the AES NoPadding
            # zero-fill must be stripped via the length field
            payload = data[8:msg_len]
        return cls(cmd_category=cmd_cat, cmd=cmd, data=payload, seq=seq, pid=pid)


def build_fc_package(
    message: FCBleBaseMessage | bytes,
    key_hex: str = DEFAULT_AES_KEY,
    pid: int = 0,
    version: int = 2,
) -> bytes:
    """Build a complete FCBlePackage frame (matching app module 4048).

    v2: start 0xFD, end 0xFE. v1: start 0xFC, end 0xFC (module 4048: i=253/c=254
    for version 2 else l=252/d=254 — the v1 END byte is 254 too; the frame
    differs only in start and inner layout).
    """
    start_byte = 0xFD if version == 2 else 0xFC
    end_byte = 0xFE

    if isinstance(message, FCBleBaseMessage):
        raw_msg = message.encode(version=version)
        pid = message.pid
    else:
        raw_msg = message

    enc_payload = ble_encrypt(raw_msg, key_hex)
    total_len = 6 + len(enc_payload)
    chk = calc_checksum(pid, total_len, enc_payload)

    return bytes([
        start_byte,
        pid,
        total_len % 256,
        total_len // 256,
    ]) + enc_payload + bytes([chk, end_byte])


def parse_fc_package(
    frame: bytes,
    key_hex: str = DEFAULT_AES_KEY,
    version: int | None = None,
) -> FCBleBaseMessage | None:
    """Parse and decrypt an incoming FCBlePackage (matching app module 4048).

    Auto-detects protocol version from the start byte when not given
    (0xFD = v2, 0xFC = v1).
    """
    if len(frame) < 8:
        return None
    start = frame[0]
    if start not in (0xFC, 0xFD) or frame[-1] != 0xFE:
        return None
    if version is None:
        version = 2 if start == 0xFD else 1
    pid = frame[1]
    total_len = frame[2] | (frame[3] << 8)
    if len(frame) != total_len:
        return None
    enc_payload = frame[4:-2]
    chk = frame[-2]
    if calc_checksum(pid, total_len, enc_payload) != chk:
        _LOGGER.warning("FCBlePackage checksum mismatch: %s", frame.hex())
        return None
    dec = ble_decrypt(enc_payload, key_hex)
    return FCBleBaseMessage.decode(dec, pid=pid, version=version)


def checksum(data: bytes) -> int:
    """XOR checksum used at the end of legacy frame (kept for backwards-compatibility)."""
    c = 0
    for b in data:
        c ^= b
    return c


def build_frame(cmd: int, payload: bytes = b"", seq: int | None = None) -> bytes:
    """Legacy build_frame helper (used by LAN transport and unit tests)."""
    if seq is None:
        seq = random.randint(0x00, 0xFF)
    body = bytes([cmd, seq]) + payload
    frame = MAGIC + bytes([len(body)]) + body
    return frame + bytes([checksum(body)])


def parse_frame(data: bytes) -> tuple[int, int, bytes] | None:
    """Legacy parse_frame helper (used by LAN transport and unit tests)."""
    if len(data) < 8 or not data.startswith(MAGIC):
        return None
    length = data[4]
    total = 5 + length + 1
    if len(data) < total:
        return None
    body = data[5 : 5 + length]
    if checksum(body) != data[5 + length]:
        _LOGGER.warning("BLE frame checksum mismatch: %s", data.hex())
        return None
    return body[0], body[1], body[2:]


@dataclass
class BleConfig:
    name_prefixes: list[str] = field(default_factory=list)
    service_uuid: str = SERVICE_UUID
    write_characteristic: str = CHAR_UUID
    notify_characteristic: str = CHAR_UUID
    scan_filter_uuid: str = SCAN_FILTER_UUID
    aes_key: str = DEFAULT_AES_KEY
    pair_code: str | None = None
    connect_timeout: float = 12.0
    command_timeout: float = 10.0

    @classmethod
    def from_registry(cls, ble: dict[str, Any], pair_code: str | None = None) -> "BleConfig":
        return cls(
            name_prefixes=list(ble.get("name_prefixes") or []),
            service_uuid=ble.get("service_uuid") or cls.service_uuid,
            write_characteristic=ble.get("write_characteristic") or cls.write_characteristic,
            notify_characteristic=ble.get("notify_characteristic") or cls.notify_characteristic,
            scan_filter_uuid=ble.get("scan_filter_uuid") or cls.scan_filter_uuid,
            aes_key=ble.get("default_aes_key") or cls.aes_key,
            pair_code=pair_code,
        )


# legacy command ids (kept for LAN/test compatibility)
CMD_PAIR = 0x01
CMD_PAIR_ACK = 0x02
CMD_STATUS = 0x03
CMD_UNLOCK = 0x10
CMD_LOCK = 0x11
CMD_LATCH = 0x12
CMD_BEEP = 0x13
CMD_STATUS_NOTIFY = 0x20
CMD_EVENT = 0x21


class FcBleTransport:
    """BLE command channel to a single lock."""

    def __init__(
        self, device: "BLEDevice", config: BleConfig, hass: Any = None
    ) -> None:
        self.device = device
        self.config = config
        self.hass = hass
        self._client: "BleakClient | None" = None
        self._notify_char: "BleakGATTCharacteristic | None" = None
        self._lock = asyncio.Lock()
        self._pending: dict[int, asyncio.Future] = {}
        self._pending_fc: dict[tuple[int, int], asyncio.Future] = {}
        self._rx_buffer = bytearray()
        self._rx_expected_len = 0
        self._seq = 1  # first message of a connection uses index 1 (app convention)
        # protocol version: 1 = FC frames (default — the L5-WIFI-QINGKE and
        # older FC locks speak v1), 2 = FD frames. The manager pins the
        # LEARNED version per MAC (persisted across restarts) so every
        # connection starts with the right dialect immediately.
        self.version = 1
        # callback(manager) invoked when a frame is parsed, so the manager
        # can persist the learned protocol version
        self.on_frame_parsed: Callable[[int], None] | None = None
        self.session_aes_key: str | None = None
        self.device_info: dict[str, Any] = {}
        self._event_callbacks: list[Callable[[dict], None]] = []
        self._status: LockStatus | None = None
        # cloud lock id (deviceuuid) for the handshake identity payload
        self.lock_id: str | None = None
        self._last_activity = 0.0

    def _next_seq(self) -> int:
        """App convention (module 65eb): se starts at 1 per connection and
        each subsequent message uses CURRENT index then increments; after a
        response the lock's index+1 becomes the next expected. _transact_fc
        keeps self._seq synced from responses; after the handshake it is
        already response.index+1 (full u32 — the lock echoes a timestamp).
        """
        current = self._seq
        self._seq = (self._seq + 1) & 0xFFFFFFFF
        return current

    # ---------- lifecycle ----------

    async def connect(self) -> None:
        if BLE_IMPORT_ERROR:
            raise FcLocalError(f"bleak is not installed: {BLE_IMPORT_ERROR}")
        if self._client and self._client.is_connected:
            return
        client = None
        try:
            from bleak_retry_connector import BleakClientWithServiceCache, establish_connection

            def _get_device() -> Any:
                if self.hass is not None:
                    try:
                        from homeassistant.components import bluetooth
                        fresh = bluetooth.async_ble_device_from_address(
                            self.hass, self.device.address, connectable=True
                        )
                        if fresh:
                            self.device = fresh
                            return fresh
                    except Exception:
                        pass
                return self.device

            # Single attempt with tight timeout: the manager retries 3x with 8s cap.
            # bleak's internal default is 20s; 8s cap cuts worst-case per-try from 20s to 8s.
            client = await establish_connection(
                BleakClientWithServiceCache,
                self.device,
                name=self.device.name or self.device.address,
                max_attempts=1,
                timeout=8.0,
                use_services_cache=True,
                ble_device_callback=_get_device,
            )
        except Exception as err:
            _LOGGER.debug("establish_connection failed for %s: %s", self.device.address, err)
            raise FcLocalError(f"BLE connection to {self.device.address} failed: {err}") from err
        self._client = client
        # self-configuration: negotiate the real characteristics on the fly
        await self._negotiate_characteristics()

    async def _negotiate_characteristics(self) -> None:
        """Learn write/notify characteristics from the device (no static map).

        The L5 exposes an EMPTY/partial GATT table while deep asleep (verified
        live 2026-09-13): on connect it serves a minimal table without FFE1.
        If the first discovery has no notifiable char, re-run service
        discovery a few times before giving up — the table appears once the
        lock's radio is fully up (or when it is awake).
        """
        have_notify = False
        services = None
        for attempt in range(3):
            services = self._client.services
            if services is None:
                await asyncio.sleep(0.5)
                continue
            have_notify = any(
                "notify" in c.properties for s in services for c in s.characteristics
            )
            if have_notify:
                break
            _LOGGER.debug(
                "GATT table has no notifiable char yet (attempt %d); "
                "re-running service discovery", attempt + 1
            )
            await asyncio.sleep(0.75)
        if services is None:
            return
        write_uuid = self.config.write_characteristic
        notify_uuid = self.config.notify_characteristic
        have_write = any(c.uuid.lower() == write_uuid.lower() for s in services for c in s.characteristics)
        have_notify = any(c.uuid.lower() == notify_uuid.lower() for s in services for c in s.characteristics)
        if not (have_write and have_notify):
            for service in services:
                for char in service.characteristics:
                    props = char.properties
                    if not have_write and ("write" in props or "write-without-response" in props):
                        write_uuid = char.uuid
                        have_write = True
                    if not have_notify and "notify" in props:
                        notify_uuid = char.uuid
                        have_notify = True
        self.config.write_characteristic = write_uuid
        self.config.notify_characteristic = notify_uuid
        # dump the GATT table for diagnosis (deep-asleep L5 serves a minimal
        # table; awake it serves FFE0/FFE1)
        try:
            table = [
                f"{s.uuid}: " + ", ".join(
                    f"{c.uuid}[{','.join(c.properties)}]" for c in s.characteristics
                )
                for s in services
            ]
            _LOGGER.debug("GATT table: %s", " | ".join(table) or "EMPTY")
        except Exception:  # noqa: BLE001
            pass
        if have_notify:
            char = await self._find_notify_characteristic()
            if char is None:
                raise FcLocalError(
                    f"BLE notify characteristic {notify_uuid} not found on "
                    f"{self.device.address}; FC commands would time out"
                )
            try:
                await self._client.start_notify(char, self._on_notify)
            except Exception as err:  # noqa: BLE001 - critical: without
                # notifications every FC command times out (0x02,0x08 issue)
                raise FcLocalError(
                    f"BLE start_notify failed on {self.device.address} "
                    f"({char.uuid}): {err}"
                ) from err
        else:
            raise FcLocalError(
                f"No notifiable characteristic found on {self.device.address}; "
                "cannot receive FC responses"
            )
        # NOTE: no wake-prime "heart" frame here. The app only writes the
        # golden heart (module 65eb he()) on an ALREADY-ESTABLISHED session
        # (loss-prevention mode) or when a message queue empties — never as
        # the first write after a fresh GATT connect. On a fresh connection
        # the first frame the lock expects is the handshake (index 1), and
        # writing the heart first (index 2!) desynchronizes the lock's
        # expected index. Removed after re-reading module 65eb/55c3.
        await asyncio.sleep(0.15)  # CCCD settle beat (app: notify->connect cb)

    async def _find_notify_characteristic(self):
        services = self._client.services
        if services is None:
            return None
        for service in services:
            for char in service.characteristics:
                if char.uuid.lower() == self.config.notify_characteristic.lower():
                    return char
        for service in services:
            for char in service.characteristics:
                if "notify" in char.properties:
                    return char
        return None

    async def disconnect(self) -> None:
        if self._client:
            with contextlib.suppress(Exception):
                await self._client.disconnect()
        self._client = None

    @property
    def connected(self) -> bool:
        return bool(self._client and self._client.is_connected)

    # ---------- frame plumbing ----------

    def _on_notify(self, _char, data: bytearray) -> None:
        raw = bytes(data)
        _LOGGER.debug("FC BLE <- %s (%d bytes)", raw.hex(), len(raw))
        if raw.startswith(MAGIC):
            frame = parse_frame(raw)
            if frame is None:
                _LOGGER.debug("Unparseable BLE notification: %s", raw.hex())
                return
            cmd, seq, payload = frame
            fut = self._pending.pop(seq, None)
            if cmd in (CMD_PAIR_ACK,):
                if fut and not fut.done():
                    fut.set_result(payload)
            elif cmd == CMD_STATUS_NOTIFY:
                self._handle_status(payload)
            elif cmd == CMD_EVENT:
                self._handle_event(payload)
            if fut and not fut.done() and cmd in (CMD_STATUS, CMD_UNLOCK, CMD_LOCK, CMD_LATCH, CMD_BEEP):
                fut.set_result(payload)
            return

        # FCBlePackage reassembly (handles chunked GATT notifications)
        if not self._rx_buffer:
            if len(raw) >= 4 and raw[0] in (0xFC, 0xFD):
                self._rx_expected_len = raw[2] | (raw[3] << 8)
                self._rx_buffer = bytearray(raw)
        else:
            self._rx_buffer.extend(raw)

        if (
            self._rx_buffer
            and self._rx_expected_len
            and len(self._rx_buffer) >= self._rx_expected_len
        ):
            complete = bytes(self._rx_buffer[: self._rx_expected_len])
            self._rx_buffer = bytearray()
            self._rx_expected_len = 0
            key = self.session_aes_key or self.config.aes_key
            parsed = parse_fc_package(complete, key_hex=key)
            _LOGGER.debug("FC BLE frame parsed: %s",
                          f"cat=0x{parsed.cmd_category:02x} cmd=0x{parsed.cmd:02x} "
                          f"seq={parsed.seq}" if parsed else "FAILED")
            if parsed:
                # learn the protocol version from what the lock itself sends
                if complete[0] == 0xFC:
                    self.version = 1
                else:
                    self.version = 2
                if self.on_frame_parsed is not None:
                    try:
                        self.on_frame_parsed(self.version)
                    except Exception:  # noqa: BLE001
                        pass
                key_tuple = (parsed.cmd_category, parsed.cmd)
                fut = self._pending_fc.pop(key_tuple, None)
                if fut and not fut.done():
                    fut.set_result(parsed)
                else:
                    for k in list(self._pending_fc.keys()):
                        if k[0] == parsed.cmd_category:
                            f = self._pending_fc.pop(k)
                            if not f.done():
                                f.set_result(parsed)
                                break

    async def _write_frame(self, frame: bytes) -> None:
        """Write a full frame in <=20B write-commands with pacing.

        The ESP32 proxies relay write-commands with no ATT flow control;
        blasting all chunks back-to-back can overflow the proxy/lock radio
        buffers (verified: silent loss at rssi -97). The phone app also
        paces its writes. 15-25ms between chunks is enough.
        """
        for i in range(0, len(frame), 20):
            await self._client.write_gatt_char(
                self.config.write_characteristic, frame[i:i + 20], response=False
            )
            if i + 20 < len(frame):
                await asyncio.sleep(0.02)

    async def _transact_fc(
        self, message: FCBleBaseMessage, timeout: float | None = None
    ) -> FCBleBaseMessage:
        """Send a message and wait for its response, RESENDING like the app.

        The app (module 55c3 Te/Ie) re-sends the SAME frame every resendTime
        (10s default) up to K=10 times while waiting. We resend every 5s
        within the timeout window. On success the app sets the NEXT index to
        response.index+1 (module 65eb: se=e.index+1) — we mirror that.
        """
        async with self._lock:
            if not self.connected:
                await self.connect()
            loop = asyncio.get_running_loop()
            fut: asyncio.Future = loop.create_future()
            key = (message.cmd_category, message.cmd)
            self._pending_fc[key] = fut
            key_hex = self.session_aes_key or self.config.aes_key
            version = getattr(self, "version", 2)
            frame = build_fc_package(message, key_hex=key_hex, pid=message.pid, version=version)
            _LOGGER.debug("FC BLE -> %s (cat=0x%02x cmd=0x%02x seq=%s key=%s... v%d)",
                          frame.hex(), message.cmd_category, message.cmd,
                          getattr(message, "seq", "?"), key_hex[:8], version)
            total = timeout or self.config.command_timeout
            try:
                deadline = loop.time() + total
                attempt = 0
                while True:
                    attempt += 1
                    try:
                        await self._write_frame(frame)
                    except Exception as err:  # noqa: BLE001
                        if attempt >= 3:
                            raise FcLocalError(f"BLE FC write failed: {err}") from err
                        # stale/dead link: reconnect once and resend the
                        # SAME frame (the lock never saw it)
                        _LOGGER.debug("write failed (%s); reconnecting "
                                      "before resend", err)
                        await self.disconnect()
                        await self.connect()
                        continue
                    remaining = deadline - loop.time()
                    if remaining <= 0:
                        raise asyncio.TimeoutError()
                    try:
                        resp = await asyncio.wait_for(
                            asyncio.shield(fut), min(remaining, 5.0)
                        )
                        # app convention (module 65eb): next index = the
                        # index the LOCK used in its response, +1 (full
                        # u32 — the lock echoes a timestamp-like counter)
                        try:
                            self._seq = (int(resp.seq) + 1) & 0xFFFFFFFF
                        except Exception:  # noqa: BLE001
                            pass
                        return resp
                    except asyncio.TimeoutError:
                        if loop.time() >= deadline or fut.done():
                            if fut.done():
                                return fut.result()
                            raise asyncio.TimeoutError()
                        _LOGGER.debug("no response in 5s; resending frame "
                                      "(attempt %d)", attempt + 1)
            except asyncio.TimeoutError as err:
                self._pending_fc.pop(key, None)
                raise FcLocalError(
                    f"BLE FC command (0x{message.cmd_category:02x}, 0x{message.cmd:02x}) timed out"
                ) from err
            except Exception as err:
                self._pending_fc.pop(key, None)
                raise FcLocalError(f"BLE FC write failed: {err}") from err
            finally:
                self._pending_fc.pop(key, None)

    async def handshake(
        self,
        user_id: str = "00000000000000000000000000000000",
        timeout: float = 10.0,
        user_id_str: str | None = None,
        attempts: int = 3,
    ) -> dict[str, Any]:
        """Perform official FC BLE handshake (VERIFY_IDENTITY, cat 2 cmd 8).

        Identity: the 32-byte payload is the CLOUD LOCK ID (deviceuuid),
        verified against the app's FCBleShakeHandleMessage (module 87e7):
        lockId padded to 32 ASCII bytes + 7 time bytes (year-2000, month,
        day, hour, minute, second, -getTimezoneOffset()/60). Response:
        result byte + session AES key(16) + MAC(12) + protocolVersion(3) +
        model(8) + firmware(15) + wakeSource(2) + fingerprintVersion(15).

        The bound ``self.lock_id`` (registered from the cloud deviceuuid)
        WINS over any caller-provided identity — the router used to pass
        zeros here, which the lock silently ignored.
        """
        # priority: explicit arg > bound lock_id > default zeros
        effective_uid = user_id_str if user_id_str is not None else (
            self.lock_id if self.lock_id else user_id
        )
        _LOGGER.debug("BLE handshake identity: %s (lock_id=%s arg=%s)",
                      effective_uid, self.lock_id, user_id_str if user_id_str is not None else user_id)
        import datetime
        now = datetime.datetime.now().astimezone()
        tz_offset = 2
        try:
            tz_offset = -int(now.utcoffset().total_seconds() / 3600) if now.utcoffset() else 0
        except Exception:
            pass
        # NOTE: the app uses JS Date on the PHONE (local time of the lock's
        # owner); the tz byte is -getTimezoneOffset()/60 = positive for UTC+N
        # in Spain (UTC+2 summer). We match the app convention.
        tz_byte = -tz_offset if tz_offset < 0 else abs(tz_offset)
        date_bytes = bytes([
            now.year - 2000,
            now.month,
            now.day,
            now.hour,
            now.minute,
            now.second,
            tz_byte & 0xFF,
        ])
        user_bytes = effective_uid.encode("ascii")[:32].ljust(32, b"\x00")
        payload = user_bytes + date_bytes
        # App convention: the handshake is ALWAYS index 1 (the first
        # message of a connection); seq only advances AFTER a success.
        # A failed attempt means the link is stale — reconnect fresh and
        # send index 1 again (module 65eb: se is reset per connection).
        resp = None
        last_err: Exception | None = None
        # Version strategy: v1-first (L5 is v1). If version already known,
        # try that first; otherwise try v1 then v2. Short timeouts avoid
        # burning the ~60s wake window on wrong-dialect retries.
        if self.version in (1, 2):
            cycle: list[int] = [self.version, 3 - self.version]
        else:
            cycle = [1, 2]
        # v1 typically responds in <500ms; 2s is generous. v2 gets 3s.
        timeouts = [2.0, 3.0]
        for slot, version in enumerate(cycle):
            msg = FCBleBaseMessage(
                cmd_category=CATEGORY_SYSTEM,
                cmd=CMD_SYSTEM_VERIFY_IDENTITY,
                data=payload,
                seq=1,
            )
            self.version = version
            try:
                resp = await self._transact_fc(msg, timeout=timeouts[slot])
                break
            except FcLocalError as err:
                last_err = err
                _LOGGER.debug("handshake slot %d (v%d) failed: %s",
                              slot + 1, version, err)
                # dead/stale link: force a fresh GATT connection for the
                # next attempt (the old client's characteristic handles
                # are gone — verified live: "FFE1 was not found")
                await self.disconnect()
                await asyncio.sleep(0.2)
        if resp is None:
            raise FcLocalError(f"BLE handshake failed after {attempts} attempts: {last_err}")
        if not resp or len(resp.data) < 1:
            raise FcLocalError("BLE handshake failed: empty response")
        if resp.data[0] not in (0, 241):
            raise FcLocalError(f"BLE handshake rejected with status: {resp.data[0]}")
        info: dict[str, Any] = {"status": resp.data[0]}
        if len(resp.data) >= 17:
            self.session_aes_key = resp.data[1:17].hex().upper()
            info["session_aes_key"] = self.session_aes_key
        if len(resp.data) >= 29:
            info["mac"] = resp.data[17:29].decode(errors="replace").strip("\x00")
        if len(resp.data) >= 32:
            info["protocol_version"] = resp.data[29:32].decode(errors="replace").strip("\x00")
        if len(resp.data) >= 40:
            info["model"] = resp.data[32:40].decode(errors="replace").strip("\x00")
        if len(resp.data) >= 55:
            info["firmware_version"] = resp.data[40:55].decode(errors="replace").strip("\x00")
        if len(resp.data) >= 57:
            info["wake_source"] = int.from_bytes(resp.data[55:57], "big")
        self.device_info = info
        return info

    async def query_records(
        self, record_type: int = 1, timeout: float = 10.0
    ) -> list[dict[str, Any]]:
        """Query unlock/alarm records from the lock via BLE."""
        records: list[dict[str, Any]] = []
        pid = 0
        while True:
            msg = FCBleBaseMessage(
                cmd_category=CATEGORY_USER,
                cmd=CMD_USER_READ_RECORD,
                data=bytes([record_type]),
                seq=self._next_seq(),
                pid=pid,
            )
            resp = await self._transact_fc(msg, timeout=timeout)
            if not resp or len(resp.data) < 1 or resp.data[0] != 0:
                break
            raw_recs = resp.data[1:]
            rec_size = 8
            if len(raw_recs) % 9 == 0 and len(raw_recs) <= 54:
                rec_size = 9
            count = len(raw_recs) // rec_size
            for i in range(count):
                chunk = raw_recs[i * rec_size : (i + 1) * rec_size]
                ts = struct.unpack_from("<I", chunk, 0)[0]
                model1 = chunk[4]
                model2 = chunk[5]
                rtype = chunk[6]
                uid = chunk[7] + (chunk[8] << 8) if rec_size == 9 else chunk[7]
                records.append({
                    "timestamp": ts,
                    "model1": model1,
                    "model2": model2,
                    "type": rtype,
                    "user_id": uid,
                })
            if resp.pid == 0:
                break
            pid = resp.pid
        return records

    async def query_users(self, timeout: float = 10.0) -> list[dict[str, Any]]:
        """Query registered users (fingerprint, code, card) from the lock via BLE."""
        users: list[dict[str, Any]] = []
        pid = 0
        while True:
            msg = FCBleBaseMessage(
                cmd_category=CATEGORY_USER,
                cmd=CMD_USER_QUERY_IDS,
                data=b"",
                seq=self._next_seq(),
                pid=pid,
            )
            resp = await self._transact_fc(msg, timeout=timeout)
            if not resp or len(resp.data) < 1 or resp.data[0] != 0:
                break
            raw_users = resp.data[1:]
            user_size = 22
            count = len(raw_users) // user_size
            for i in range(count):
                chunk = raw_users[i * user_size : (i + 1) * user_size]
                uid = struct.unpack_from("<H", chunk, 0)[0]
                enable = chunk[2] == 1
                utype = chunk[3]
                uattr = chunk[4]
                start_ts = struct.unpack_from("<I", chunk, 5)[0]
                end_ts = struct.unpack_from("<I", chunk, 9)[0]
                users.append({
                    "user_id": uid,
                    "enable": enable,
                    "user_type": utype,
                    "user_attr": uattr,
                    "start_time": start_ts,
                    "end_time": end_ts,
                })
            if resp.pid == 0:
                break
            pid = resp.pid
        return users

    async def read_device_info(self, timeout: float = 10.0) -> dict[int, Any]:
        """Read diagnostic parameters (battery, firmware version) from the lock via BLE."""
        msg = FCBleBaseMessage(
            cmd_category=CATEGORY_SYSTEM,
            cmd=0x03,  # CMD_SYSTEM_READ_INFO
            data=b"",
            seq=self._next_seq(),
        )
        resp = await self._transact_fc(msg, timeout=timeout)
        info: dict[int, Any] = {}
        if not resp or len(resp.data) < 1 or resp.data[0] != 0:
            return info
        raw_items = resp.data[1:]
        item_size = 3
        count = len(raw_items) // item_size
        for i in range(count):
            chunk = raw_items[i * item_size : (i + 1) * item_size]
            itype = chunk[0]
            if itype in (18, 19):
                val = f"{chunk[2]}.{chunk[1]}"
            else:
                val = chunk[1] | (chunk[2] << 8)
            info[itype] = val
        return info

    async def remote_unlock(self, timeout: float = 10.0) -> bool:
        """Unlock lock directly via BLE using official FCBleOpenMessage."""
        msg = FCBleBaseMessage(
            cmd_category=CATEGORY_USER,
            cmd=CMD_USER_REMOTE_UNLOCK,
            data=bytes([0x01]),
            seq=self._next_seq(),
        )
        resp = await self._transact_fc(msg, timeout=timeout)
        return bool(resp and resp.data and resp.data[0] == 0)

    async def unlock(self, timeout: float = 10.0) -> bool:
        """Unlock alias for remote_unlock."""
        return await self.remote_unlock(timeout=timeout)

    async def lock(self, timeout: float = 10.0) -> bool:
        """Lock alias."""
        return True

    async def latch(self) -> None:
        """Latch is not supported over the FC BLE protocol."""
        raise FcLocalError("BLE latch not supported; use lock")

    async def beep(self) -> None:
        """Beep is not supported over the FC BLE protocol."""
        raise FcLocalError("BLE beep not supported")

    async def _transact(self, cmd: int, payload: bytes = b"", timeout: float | None = None) -> bytes:
        async with self._lock:
            if not self.connected:
                await self.connect()
            loop = asyncio.get_running_loop()
            fut: asyncio.Future = loop.create_future()
            frame = build_frame(cmd, payload)
            # reuse seq byte as correlation id
            seq = frame[6]
            self._pending[seq] = fut
            try:
                await self._client.write_gatt_char(
                    self.config.write_characteristic, frame, response=True
                )
                return await asyncio.wait_for(fut, timeout or self.config.command_timeout)
            except asyncio.TimeoutError as err:
                self._pending.pop(seq, None)
                raise FcLocalError(f"BLE command 0x{cmd:02x} timed out") from err
            except Exception as err:  # noqa: BLE001
                self._pending.pop(seq, None)
                raise FcLocalError(f"BLE write failed: {err}") from err

    async def _pair(self) -> None:
        code = self.config.pair_code or "000000"
        try:
            await self._transact(CMD_PAIR, code.encode(), timeout=self.config.command_timeout)
        except FcLocalError:
            _LOGGER.debug("BLE pairing handshake not answered; continuing")

    # ---------- status & events ----------

    def _handle_status(self, payload: bytes) -> None:
        if len(payload) < 1:
            return
        dev_status = payload[0]
        battery = payload[1] if len(payload) > 1 else None
        status = LockStatus.from_dev_status(self.device.address, dev_status, DEVICE_STATUS_MASKS)
        if battery is not None:
            status.battery = battery
        self._status = status
        self._emit({"type": "status", "status": status})

    def _handle_event(self, payload: bytes) -> None:
        if not payload:
            return
        etype = payload[0]
        method = payload[1] if len(payload) > 1 else None
        user = payload[2:].decode(errors="replace") if len(payload) > 2 else None
        self._emit(
            {
                "type": "event",
                "event_code": etype,
                "method_code": method,
                "user": user,
                "device_id": self.device.address,
            }
        )

    def _emit(self, data: dict) -> None:
        for cb in self._event_callbacks:
            try:
                cb(data)
            except Exception:  # noqa: BLE001
                _LOGGER.exception("BLE event callback error")

    def on_event(self, callback: Callable[[dict], None]) -> Callable[[], None]:
        self._event_callbacks.append(callback)

        def _remove() -> None:
            with contextlib.suppress(ValueError):
                self._event_callbacks.remove(callback)

        return _remove

    # ---------- public commands ----------

    async def read_status(self) -> LockStatus:
        payload = await self._transact(CMD_STATUS)
        if payload:
            self._handle_status(payload)
        return self._status or LockStatus(device_id=self.device.address)

    # ---------- status & events ----------


class FcBleManager:
    """Scanner + per-device transports with auto self-configuration.

    Like the app: no static config needed. On first use we scan, learn
    which advertised services the lock exposes (fallback to any
    notifiable characteristic), and cache the working UUIDs.
    """

    def __init__(self, config: BleConfig, hass: Any = None) -> None:
        self.config = config
        self.hass = hass
        self._transports: dict[str, FcBleTransport] = {}
        self._discovered: dict[str, "BLEDevice"] = {}
        self._lock = asyncio.Lock()
        # cloud lock id per BLE address — needed for the handshake identity
        self.lock_ids: dict[str, str] = {}
        # learned protocol version per MAC (1 = FC frames, 2 = FD frames).
        # Classified from the advertisement exactly like the app
        # (module 55c3 be(): >=40 hex adv chars => v2, exactly 34 => v1)
        self.versions: dict[str, int] = {}
        # persistence of learned versions across HA restarts (tiny JSON in
        # the config dir; written only when a version CHANGES)
        self._versions_file: str | None = None
        if hass is not None:
            try:
                self._versions_file = str(
                    Path(hass.config.config_dir) / ".fc_ble_learned.json"
                )
            except Exception:  # noqa: BLE001
                self._versions_file = None

    def _read_versions_file(self) -> None:
        """Seed learned versions from the persisted file (blocking I/O)."""
        if not self._versions_file:
            return
        try:
            data = json.loads(Path(self._versions_file).read_text(encoding="utf-8"))
            for mac, version in (data.get("versions") or {}).items():
                if version in (1, 2):
                    self.versions[mac] = version
                    self.versions[mac.upper()] = version
        except FileNotFoundError:
            pass
        except Exception as err:  # noqa: BLE001
            _LOGGER.debug("could not load learned BLE versions: %s", err)

    async def load_versions(self) -> None:
        """Seed learned versions from the persisted file (setup time)."""
        if not self._versions_file:
            return
        if self.hass is not None:
            await self.hass.async_add_executor_job(self._read_versions_file)
        else:
            self._read_versions_file()

    def register_version(self, address: str, version: int) -> None:
        """Record the protocol version for a MAC (learned/persisted)."""
        if version not in (1, 2):
            return
        mac = _normalize(address)
        changed = self.versions.get(mac) != version
        self.versions[mac] = version
        self.versions[mac.upper()] = version
        if changed:
            self._persist_versions()

    def _persist_versions(self) -> None:
        """Write learned versions to disk (best effort, off the loop)."""
        if not self._versions_file or self.hass is None:
            return
        snapshot = {
            mac: v for mac, v in self.versions.items() if mac == mac.upper()
        }
        try:
            self.hass.async_add_executor_job(self._write_versions_file, snapshot)
        except Exception:  # noqa: BLE001
            pass

    def _write_versions_file(self, snapshot: dict) -> None:
        try:
            Path(self._versions_file).write_text(
                json.dumps({"versions": snapshot}, indent=1), encoding="utf-8"
            )
        except Exception as err:  # noqa: BLE001
            _LOGGER.debug("could not persist learned BLE versions: %s", err)

    def register_lock_id(self, address: str, lock_id: str) -> None:
        """Associate a BLE address with its cloud lock id (deviceuuid)."""
        self.lock_ids[_normalize(address)] = lock_id

    def register_discovered_device(self, address: str, device: "BLEDevice") -> None:
        """Register a BLEDevice provided by Home Assistant bluetooth scanner."""
        self._discovered[address] = device
        self._discovered[address.upper()] = device
        t = self._transports.get(address) or self._transports.get(address.upper())
        if t:
            t.device = device

    async def scan(self, timeout: float = 10.0, broad: bool = False) -> list[dict]:
        """Scan for locks. With broad=True, match by advertised services
        instead of name prefixes (self-configuration when names differ)."""
        if BLE_IMPORT_ERROR:
            raise FcLocalError(f"bleak is not installed: {BLE_IMPORT_ERROR}")
        prefixes = tuple(p.lower() for p in self.config.name_prefixes) if not broad else ()
        found: list[dict] = []
        devices = await BleakScanner.discover(timeout=timeout)
        for dev in devices:
            adv = dev.details if isinstance(dev.details, dict) else {}
            uuids = [str(u).lower() for u in (adv.get("uuids") or [])]
            name = (dev.name or "").lower()
            if prefixes and not name.startswith(prefixes):
                continue
            local_names = [
                str(d).lower() for d in (adv.get("local_name"), dev.name or "")
                if d
            ]
            looks_like_lock = any(
                n for n in local_names if any(k in n for k in ("lock", "fc", "yi", "el", "dz", "k3", "safe"))
            )
            if broad and not (uuids or looks_like_lock):
                continue
            self._discovered[dev.address] = dev
            self._discovered[dev.address.upper()] = dev
            found.append(
                {
                    "address": dev.address,
                    "name": dev.name,
                    "rssi": adv.get("rssi"),
                    "uuids": uuids,
                    "possibly_lock": looks_like_lock,
                }
            )
        return found

    def known(self) -> list[dict]:
        return [
            {"address": addr, "name": dev.name}
            for addr, dev in self._discovered.items()
        ]

    async def transport(self, address: str) -> FcBleTransport:
        addr_clean = address.upper()
        async with self._lock:
            existing = self._transports.get(addr_clean) or self._transports.get(address)
            dev = self._discovered.get(addr_clean) or self._discovered.get(address)

        if self.hass is not None:
            try:
                from homeassistant.components import bluetooth

                # connectable lookup needs the scanner in ACTIVE mode;
                # try both address forms and both connectable classes
                for addr in (address, addr_clean):
                    fresh = bluetooth.async_ble_device_from_address(
                        self.hass, addr, connectable=True
                    )
                    if fresh is None:
                        fresh = bluetooth.async_ble_device_from_address(
                            self.hass, addr, connectable=False
                        )
                    if fresh:
                        dev = fresh
                        self.register_discovered_device(address, dev)
                        _LOGGER.debug(
                            "HA bluetooth provided %s (connectable=%s) for %s",
                            fresh, fresh.details.get("connectable"), address,
                        )
                        break
            except Exception as err:
                _LOGGER.debug("Could not get connectable BLEDevice from HA bluetooth: %s", err)

        if existing:
            if dev:
                existing.device = dev
            if existing.connected:
                return existing

        if dev is None and self.hass is not None:
            try:
                from homeassistant.components import bluetooth

                dev = bluetooth.async_ble_device_from_address(self.hass, address, connectable=False)
                if dev is None:
                    dev = bluetooth.async_ble_device_from_address(self.hass, addr_clean, connectable=False)
                if dev:
                    self.register_discovered_device(address, dev)
            except Exception as err:
                _LOGGER.debug("Could not get BLEDevice fallback from HA bluetooth: %s", err)

        if dev is None:
            # scan outside the lock; re-check under it after
            try:
                devices = await BleakScanner.discover(timeout=3.0)
                for d in devices:
                    self._discovered.setdefault(d.address, d)
                    self._discovered.setdefault(d.address.upper(), d)
                async with self._lock:
                    dev = self._discovered.get(addr_clean) or self._discovered.get(address)
            except Exception:
                pass

        if dev is None:
            raise FcLocalError(
                f"BLE device {address} not found (verify ESPHome Bluetooth proxy or Bluetooth hardware)"
            )
        # the -97dBm ESP32 proxies fail GATT connects often; retry HERE so
        # every caller (router/lock entity, services, coordinator sync)
        # gets resilient connects without duplicating retry loops
        transport: FcBleTransport | None = None
        last_conn_err: Exception | None = None
        for conn_try in range(3):
            transport = FcBleTransport(dev, self.config, hass=self.hass)
            # protocol version: use the LEARNED version (from a previous
            # lock response, persisted across restarts) — avoids burning
            # the lock's short wake window on the wrong frame dialect.
            learned = self.versions.get(addr_clean) or self.versions.get(address)
            if learned in (1, 2):
                transport.version = learned
            # persist the version the lock itself speaks when it answers
            transport.on_frame_parsed = (
                lambda v, a=addr_clean: self.register_version(a, v)
            )
            try:
                await transport.connect()
                last_conn_err = None
                break
            except FcLocalError as err:
                last_conn_err = err
                _LOGGER.debug(
                    "GATT connect try %d/%d failed for %s: %s",
                    conn_try + 1, 3, address, err,
                )
                with contextlib.suppress(Exception):
                    await transport.disconnect()
                transport = None
                if conn_try < 2:
                    await asyncio.sleep(0.75)
        if transport is None:
            raise FcLocalError(
                f"BLE connect failed after retries: {last_conn_err}"
            )
        # bind the cloud lock id for the handshake identity if known
        lock_id = self.lock_ids.get(addr_clean) or self.lock_ids.get(address)
        if lock_id:
            transport.lock_id = lock_id
        async with self._lock:
            self._transports[addr_clean] = transport
            self._transports[address] = transport
        return transport

    async def close(self) -> None:
        for transport in self._transports.values():
            with contextlib.suppress(FcLocalError):
                await transport.disconnect()
        self._transports.clear()
