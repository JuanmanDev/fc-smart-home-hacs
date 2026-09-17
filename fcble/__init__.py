"""FC (Fingercrystal) BLE protocol library for L5-WIFI-QINGKE locks.

Wire protocol reverse-engineered from the official app's H5 control page
bundle (``Lock_Controller-4.5.11-*.js``, extracted 2026-09-12) and verified
byte-for-byte against a real AES-encrypted frame captured inside the bundle:

    FD FF 16 00 08 8AAF3DC1ABE8D57CCBB83CAE35C2AF 6B FE

which decrypts (key = raw bytes of the lock's bluetoothKey) to the inner
message ``09 00 | 02 00 00 00 | F0 30 | CB`` — i.e. len=9 LE, index=2 LE,
category=0xF0 (SPECIAL), cmd=0x30, inner-xor=0xCB.

## Frame format (``FCBlePackage`` — version 2, our lock)

    [0]     start     0xFD
    [1]     pid       package id (0 for us)
    [2..3]  length    TOTAL frame length (start..end inclusive), LE
    [4..n]  payload   AES-128-ECB of the inner message (see below)
    [n-1]   checksum  XOR of pid ^ lenLo ^ lenHi ^ (every payload byte)
    [n]     end        0xFE

## Inner message (``FCBleBaseMessage.getBytes(2)`` — the AES plaintext)

    [0..1]  length    LE u16 = 9 + len(data)  (counts the xor byte too)
    [2..5]  index     LE u32 sequence number (starts at 1, +1 each message)
    [6]     category  2=SYSTEM 4=USER 8=RECORD 16=WARN 240=SPECIAL
    [7]     cmd       opcode (FCBleCMD table)
    [8..]   data      command payload
    [last]  data_xor  XOR of lenLo ^ lenHi ^ category ^ cmd ^ data bytes
                       (the golden Android frame also XORs the index bytes —
                       ``xor_include_index=True`` reproduces that variant)

The plaintext is zero-padded to a 16-byte multiple (NoPadding) before AES.

## Crypto (``bleEncrypt``/``bleDecrypt``)

- AES-128-ECB, key = **raw 16 bytes** parsed from the 32-char hex
  ``bluetoothKey`` string (CryptoJS ``enc.Hex.parse``). The lock's
  ``bluetoothKey`` from the cloud = ``4CADB87095639211A1303639D98E9150``
  (equals the app DEFAULT_AES_KEY).
- First message (handshake) uses bluetoothKey; the handshake RESPONSE
  returns a per-session ``aeskey`` (16 raw bytes, hex-rendered) used for
  every subsequent message (app: ``de = e.aeskey``).

## Verified commands (FCBleCMD table from module "6bf4")

- VERIFY_IDENTITY (handshake): cat 2, cmd 8. data = lockId ASCII
  truncated/padded to 32 bytes + [year-2000, month, day, hour, minute,
  second, tz-hours]. Response data: [0]=result (0 or 241 = ok), then
  session aeskey(16) + mac(12) + protocolVersion(3) + model(8) +
  firmware(15) + wakeSource(2) + fingerprintVersion(15).
- OPEN (remote unlock): cat 4, cmd 16, data = [0x01].
- OPEN with id: cat 4, cmd 24, data = userId LE u16.
- HEARTBEAT: cat 240, cmd 2 (or 0x30 in the Android fixed frame).

## GATT (from the app bridge constants)

- scan advertise service: 0000-01fa  (the lock advertises as "L5")
- service:  0000ffe0-..., write char: 0000ffe1-... (notify on same)
"""

from __future__ import annotations

import struct
from datetime import datetime

try:
    from Crypto.Cipher import AES
    _HAS_CRYPTO = True
except ImportError:  # pragma: no cover
    _HAS_CRYPTO = False

DEFAULT_BLE_KEY = "4CADB87095639211A1303639D98E9150"

# GATT (from the app bridge: LOCK_SERVICE_UUID / WRITE_CHARACTERISTIC_UUID)
FC_SCAN_SERVICE_UUID = "000001fa-0000-1000-8000-00805f9b34fb"
FC_SERVICE_UUID = "0000ffe0-0000-1000-8000-00805f9b34fb"
FC_WRITE_CHAR_UUID = "0000ffe1-0000-1000-8000-00805f9b34fb"
FC_NOTIFY_CHAR_UUID = "0000ffe1-0000-1000-8000-00805f9b34fb"

FRAME_START = 0xFD
FRAME_END = 0xFE

# FCBleCMD categories
CATEGORY_SYSTEM = 2
CATEGORY_USER = 4
CATEGORY_RECORD = 8
CATEGORY_WARN = 16
CATEGORY_SPECIAL = 240

# opcodes (subset we need; full table in the app bundle "6bf4")
CMD_SYSTEM_HANDSHAKE = 1
CMD_SYSTEM_SET_TIME = 2
CMD_SPECIAL_HEART = 2
CMD_SYSTEM_READ_INFO = 4
CMD_SYSTEM_SET_LOCK_PARAM = 5
CMD_SYSTEM_BIND = 7
CMD_SYSTEM_VERIFY_IDENTITY = 8
CMD_SYSTEM_SET_KEEP_ALIVE_TYPE = 25
CMD_USER_REMOTE_UNLOCK = 16
CMD_USER_ID_BLE_OPEN = 24
CMD_SPECIAL_NOT_SUPPORT = 241

RESULT_OK_CODES = (0, 241)

# XOR variants observed in the wild:
XOR_JS = "js"          # H5 page formula: len ^ cat ^ cmd ^ data
XOR_ANDROID = "android"  # native heart frame: also XORs the 4 index bytes


def _key_bytes(key_hex_ascii: str) -> bytes:
    """CryptoJS enc.Hex.parse(): raw 16 bytes from the 32-char hex string."""
    return bytes.fromhex(key_hex_ascii)


def ble_encrypt(key_hex_ascii: str, data: bytes) -> bytes:
    """AES-128-ECB, key = raw bytes of key_hex_ascii, zero-padded plaintext."""
    if not _HAS_CRYPTO:
        raise RuntimeError("pycryptodome required for the FC BLE protocol")
    pad = 16 - (len(data) % 16)
    if pad != 16:  # NoPadding: zero-fill
        data = data + b"\x00" * pad
    return AES.new(_key_bytes(key_hex_ascii), AES.MODE_ECB).encrypt(data)


def ble_decrypt(key_hex_ascii: str, data: bytes) -> bytes:
    if not _HAS_CRYPTO:
        raise RuntimeError("pycryptodome required for the FC BLE protocol")
    return AES.new(_key_bytes(key_hex_ascii), AES.MODE_ECB).decrypt(data)


class FcBleMessage:
    """One inner protocol message (pre-encryption)."""

    def __init__(self, index: int, cmd_category: int, cmd: int,
                 data: bytes = b"", xor_variant: str = XOR_JS):
        self.index = index
        self.cmd_category = cmd_category
        self.cmd = cmd
        self.data = data
        self.xor_variant = xor_variant

    @property
    def length(self) -> int:
        """JS resetMessageLen: data ? dataLen+9 : 9 (xor byte included)."""
        return len(self.data) + 9

    def data_xor(self) -> int:
        chk = (self.length & 0xFF) ^ ((self.length >> 8) & 0xFF)
        chk ^= self.cmd_category ^ self.cmd
        for b in self.data:
            chk ^= b
        if self.xor_variant == XOR_ANDROID:
            idx = struct.pack("<I", self.index)
            for b in idx:
                chk ^= b
        return chk & 0xFF

    def to_bytes(self) -> bytes:
        """Inner plaintext: len LE + index LE + cat + cmd + data + xor."""
        return (
            struct.pack("<H", self.length)
            + struct.pack("<I", self.index)
            + bytes([self.cmd_category, self.cmd])
            + self.data
            + bytes([self.data_xor()])
        )

    @staticmethod
    def frame_checksum(pid: int, length: int, payload: bytes) -> int:
        chk = pid ^ (length & 0xFF) ^ ((length >> 8) & 0xFF)
        for b in payload:
            chk ^= b
        return chk & 0xFF

    def to_frame(self, key_hex_ascii: str, pid: int = 0) -> bytes:
        """Full wire frame: start/pid/len/AES(payload)/checksum/end."""
        payload = ble_encrypt(key_hex_ascii, self.to_bytes())
        length = 6 + len(payload)
        frame = bytearray()
        frame.append(FRAME_START)
        frame.append(pid & 0xFF)
        frame.extend(struct.pack("<H", length))
        frame.extend(payload)
        frame.append(self.frame_checksum(pid, length, payload))
        frame.append(FRAME_END)
        return bytes(frame)

    def __repr__(self) -> str:  # pragma: no cover
        return (f"FcBleMessage(idx={self.index} cat={self.cmd_category} "
                f"cmd={self.cmd} data={self.data.hex()})")


def parse_inner(data: bytes) -> FcBleMessage:
    """Parse a decrypted inner message (fromBytes layout)."""
    length = data[0] | (data[1] << 8)
    msg = FcBleMessage(
        index=struct.unpack("<I", data[2:6])[0],
        cmd_category=data[6],
        cmd=data[7],
        data=data[8:max(length - 1, 8)] if length > 9 else b"",
    )
    return msg


class FcBleFrameParser:
    """Accumulates BLE notification chunks into decrypted messages."""

    def __init__(self, key_hex_ascii: str):
        self.key = key_hex_ascii
        self._buf = bytearray()

    def feed(self, chunk: bytes) -> list[tuple[FcBleMessage, int]]:
        """Feed a notification chunk; returns (message, pid) pairs."""
        self._buf.extend(chunk)
        out: list[tuple[FcBleMessage, int]] = []
        while len(self._buf) >= 6:
            if self._buf[0] not in (0xFD, 0xFC):
                self._buf.pop(0)
                continue
            length = self._buf[2] | (self._buf[3] << 8)
            if length < 6 or length > 1024:
                self._buf.pop(0)
                continue
            if len(self._buf) < length:
                break
            frame = bytes(self._buf[:length])
            del self._buf[:length]
            if frame[-1] not in (0xFE, 0xFC):
                continue
            pid = frame[1]
            payload = frame[4:-2]
            if FcBleMessage.frame_checksum(pid, length, payload) != frame[-2]:
                continue  # corrupt, drop
            plain = ble_decrypt(self.key, payload)
            out.append((parse_inner(plain), pid))
        return out


def make_handshake(lock_id: str, index: int = 1,
                   key: str = DEFAULT_BLE_KEY) -> FcBleMessage:
    """CMD_SYSTEM_VERIFY_IDENTITY with lockId + local time + tz."""
    data = bytearray(lock_id.encode("ascii")[:32].ljust(32, b"\x00"))
    now = datetime.now()
    data.append(now.year - 2000)
    data.append(now.month)
    data.append(now.day)
    data.append(now.hour)
    data.append(now.minute)
    data.append(now.second)
    tz_hours = -int(now.astimezone().utcoffset().total_seconds() / 3600)
    data.append(tz_hours & 0xFF)
    return FcBleMessage(index, CATEGORY_SYSTEM, CMD_SYSTEM_VERIFY_IDENTITY,
                        bytes(data))


def make_open(index: int) -> FcBleMessage:
    """Remote unlock (app 'open'): cat 4 cmd 16, data=[0x01]."""
    return FcBleMessage(index, CATEGORY_USER, CMD_USER_REMOTE_UNLOCK, b"\x01")


def make_open_with_id(index: int, user_id: int) -> FcBleMessage:
    """Unlock credited to a user: cat 4 cmd 24, data=userId LE u16."""
    return FcBleMessage(index, CATEGORY_USER, CMD_USER_ID_BLE_OPEN,
                        struct.pack("<H", user_id))


def make_heartbeat(index: int) -> FcBleMessage:
    return FcBleMessage(index, CATEGORY_SPECIAL, CMD_SPECIAL_HEART)


def parse_handshake_response(data: bytes) -> dict:
    """Parse the VERIFY_IDENTITY response payload (after result byte).

    Layout from FCBleShakeHandsResopnseMessage.getDeviceDetail():
    [0] result, [1..16] aeskey (rendered hex), [17..28] mac,
    [29..31] protocolVersion, [32..39] model, [40..54] firmware,
    [55..56] wakeSource, [57..71] fingerprintModuleVersion.
    """
    if len(data) < 57:
        return {"result": data[0] if data else None, "raw": data.hex()}
    return {
        "result": data[0],
        "aeskey": data[1:17].hex(),
        "mac": data[17:29].decode("ascii", errors="replace").strip("\x00 "),
        "protocol_version": data[29:32].decode("ascii", errors="replace").strip("\x00 "),
        "model": data[32:40].decode("ascii", errors="replace").strip("\x00 "),
        "firmware": data[40:55].decode("ascii", errors="replace").strip("\x00 "),
        "wake_source": int.from_bytes(data[55:57], "big"),
        "fingerprint_version": (
            data[57:72].decode("ascii", errors="replace").strip("\x00 ")
            if len(data) >= 72 else ""
        ),
    }
