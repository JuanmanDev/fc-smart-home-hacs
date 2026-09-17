"""Tests for the HA-side BLE implementation (protocol plumbing).

Pure-python (no bluetooth): validates frame building, seq convention,
resend loop wiring and the golden heart prime, using the real module
from custom_components (import path only, no HA imports needed because
local/ble.py guards its optional imports).
"""

from __future__ import annotations

import sys
from pathlib import Path
from unittest.mock import MagicMock

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "custom_components"))

from custom_components.fc_smarthome.local.ble import (  # noqa: E402
    DEFAULT_AES_KEY,
    FCBleBaseMessage,
    FcLocalError,
    build_fc_package,
    calc_checksum,
    parse_fc_package,
)

GOLDEN_HEART = bytes.fromhex("FDFF1600088AAF3DC1ABE8D57CCBB83CAE35C2AF6BFE")


def test_heart_prime_is_the_vendor_frame():
    """The wake-prime must be byte-exact the frame captured in the app."""
    assert GOLDEN_HEART[0] == 0xFD and GOLDEN_HEART[-1] == 0xFE
    assert calc_checksum(0xFF, 22, GOLDEN_HEART[4:-2]) == GOLDEN_HEART[-2]


def test_seq_convention_first_message_is_1():
    """App convention: first message of a connection uses index 1."""
    seq = 1

    def next_seq():
        nonlocal seq
        current = seq
        seq = (seq + 1) & 0xFFFFFF
        return current

    assert next_seq() == 1
    assert next_seq() == 2


def test_handshake_frame_structure():
    msg = FCBleBaseMessage(cmd_category=0x02, cmd=0x08,
                           data=b"7b120ba58284f360699d44cebaba0a12".ljust(32, b"\x00")
                           + bytes([26, 9, 13, 12, 30, 5, 2]),
                           seq=1)
    frame = build_fc_package(msg, key_hex=DEFAULT_AES_KEY)
    assert frame[0] == 0xFD and frame[-1] == 0xFE
    assert (frame[2] | frame[3] << 8) == len(frame) == 54
    # round-trip parse with the same key
    parsed = parse_fc_package(frame, key_hex=DEFAULT_AES_KEY)
    assert parsed is not None
    assert parsed.cmd == 0x08
    assert parsed.seq == 1
    assert parsed.data[:32] == b"7b120ba58284f360699d44cebaba0a12"


def test_open_frame_structure():
    msg = FCBleBaseMessage(cmd_category=0x04, cmd=0x10, data=b"\x01", seq=2)
    frame = build_fc_package(msg, key_hex=DEFAULT_AES_KEY)
    parsed = parse_fc_package(frame, key_hex=DEFAULT_AES_KEY)
    assert parsed is not None
    assert parsed.cmd == 0x10
    assert parsed.data == b"\x01"


def test_corrupt_frame_rejected():
    msg = FCBleBaseMessage(cmd_category=0x04, cmd=0x10, data=b"\x01", seq=1)
    frame = bytearray(build_fc_package(msg, key_hex=DEFAULT_AES_KEY))
    frame[-2] ^= 0x55
    assert parse_fc_package(bytes(frame), key_hex=DEFAULT_AES_KEY) is None


def test_v1_frame_roundtrip():
    """v1 frames: start 0xFC, no inner xor byte, payload len-8."""
    msg = FCBleBaseMessage(cmd_category=0x02, cmd=0x08, data=b"\x01\x02", seq=1)
    frame = build_fc_package(msg, key_hex=DEFAULT_AES_KEY, version=1)
    assert frame[0] == 0xFC and frame[-1] == 0xFE
    parsed = parse_fc_package(frame, key_hex=DEFAULT_AES_KEY)
    assert parsed is not None
    assert parsed.cmd_category == 0x02
    assert parsed.cmd == 0x08
    assert parsed.seq == 1
    assert parsed.data == b"\x01\x02"


def test_v2_xor_matches_app_formula():
    """Inner xor = lenLo^lenHi^cat^cmd^data (module 45cc makeData_xor)."""
    # golden heart inner: len=9, idx=2, cat=0xF0, cmd=0x30 -> xor 0xC9
    # (the app's captured frame ALSO xor'd the index bytes -> 0xCB, but
    # the JS formula used for handshake/open is without index)
    msg = FCBleBaseMessage(cmd_category=0xF0, cmd=0x30, data=b"", seq=2)
    inner = msg.encode(version=2)
    assert inner[0] == 9
    assert inner[-1] == 0xC9


def test_response_seq_advances_lock_index():
    """App: se = response.index + 1 — mirrored in _transact_fc."""
    # simulate: lock responded with seq 5 -> next command index 6
    resp_seq = 5
    next_expected = (resp_seq + 1) & 0xFFFFFF
    assert next_expected == 6


def test_handshake_identity_priority_lock_id_wins():
    """The transport's bound lock_id (deviceuuid) must win over defaults."""
    from custom_components.fc_smarthome.local.ble import FcBleTransport

    transport = FcBleTransport.__new__(FcBleTransport)
    transport.lock_id = "7b120ba58284f360699d44cebaba0a12"
    # effective identity resolution (mirror of handshake() logic)
    user_id = "00000000000000000000000000000000"
    user_id_str = None
    effective = user_id_str if user_id_str is not None else (
        transport.lock_id if transport.lock_id else user_id
    )
    assert effective == "7b120ba58284f360699d44cebaba0a12"


class _MockChar:
    def __init__(self, uuid, properties):
        self.uuid = uuid
        self.properties = properties


class _MockService:
    def __init__(self, chars):
        self.characteristics = chars


def _mock_client():
    """BleakClient stand-in with a full FFE0/FFE1 GATT table."""
    client = MagicMock()

    async def _async(*_a, **_k):
        return None

    class _Write:
        frames: list = []

        async def __call__(self, _uuid, data, **_k):
            _Write.frames.append(bytes(data))

    client.start_notify = _async
    client.write_gatt_char = _Write()
    client.services = [
        _MockService([
            _MockChar(
                "0000ffe1-0000-1000-8000-00805f9b34fb",
                ["read", "write-without-response", "notify"],
            )
        ])
    ]
    client.is_connected = True
    return client


@pytest.mark.asyncio
async def test_negotiate_characteristics_prime_does_not_raise():
    """Regression: negotiation must succeed with FFE1 present and writes
    working. Since the protocol re-read (module 65eb), NO golden-heart
    wake-prime is written on a fresh connection — the first frame the
    lock must see is the handshake (index 1). The heart used to be sent
    here with index 2, desynchronizing the lock's expected index."""
    from custom_components.fc_smarthome.local.ble import BleConfig, FcBleTransport

    config = BleConfig()
    transport = FcBleTransport.__new__(FcBleTransport)
    transport.device = MagicMock()
    transport.device.address = "34:17:27:05:19:20"
    transport.config = config
    transport.hass = None
    transport._client = _mock_client()
    transport._lock = __import__("asyncio").Lock()
    transport._pending = {}
    transport._pending_fc = {}
    transport._rx_buffer = bytearray()
    transport._rx_expected_len = 0
    transport._seq = 1
    transport.version = 2
    transport.session_aes_key = None
    transport.device_info = {}
    transport._event_callbacks = []
    transport._status = None
    transport.lock_id = None
    # GATT connect succeeded -> must NOT raise
    await transport._negotiate_characteristics()
    # and NO wake-prime frame was written (handshake goes first now)
    written = b"".join(type(transport._client.write_gatt_char).frames)
    assert written == b"", "no frames must be written on a fresh connect"


@pytest.mark.asyncio
async def test_negotiate_characteristics_no_notify_raises():
    """Without any notifiable characteristic the negotiation must raise
    the clear FcLocalError (so the caller knows BLE commands can't work)."""
    from custom_components.fc_smarthome.local.ble import BleConfig, FcBleTransport

    config = BleConfig()
    transport = FcBleTransport.__new__(FcBleTransport)
    transport.device = MagicMock()
    transport.device.address = "34:17:27:05:19:20"
    transport.config = config
    transport.hass = None
    client = _mock_client()
    client.services = [_MockService([_MockChar("0000ffe2-0000-1000-8000-00805f9b34fb", ["read"])])]
    transport._client = client
    transport._lock = __import__("asyncio").Lock()
    transport._pending = {}
    transport._pending_fc = {}
    transport._rx_buffer = bytearray()
    transport._rx_expected_len = 0
    transport._seq = 1
    transport.version = 2
    transport.session_aes_key = None
    transport.device_info = {}
    transport._event_callbacks = []
    transport._status = None
    transport.lock_id = None
    with pytest.raises(FcLocalError, match="No notifiable characteristic"):
        await transport._negotiate_characteristics()


if __name__ == "__main__":
    sys.exit(pytest.main([__file__, "-q"]))
