"""Offline unit tests for the fcble protocol (no hardware needed).

Run:  python -m pytest tests/test_fcble_protocol.py -q

Golden vector: the real BLE frame captured inside the official app bundle:
    FD FF 16 00 08 8AAF3DC1ABE8D57CCBB83CAE35C2AF 6B FE
"""

from __future__ import annotations

import struct
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import pytest

from fcble import (
    CATEGORY_SYSTEM,
    CATEGORY_USER,
    CMD_SYSTEM_VERIFY_IDENTITY,
    CMD_USER_ID_BLE_OPEN,
    CMD_USER_REMOTE_UNLOCK,
    DEFAULT_BLE_KEY,
    FcBleFrameParser,
    FcBleMessage,
    XOR_ANDROID,
    ble_decrypt,
    ble_encrypt,
    make_handshake,
    make_open,
    make_open_with_id,
    parse_handshake_response,
)

GOLDEN_HEX = "FDFF1600088AAF3DC1ABE8D57CCBB83CAE35C2AF6BFE"
GOLDEN_INNER = bytes.fromhex("090002000000F030CB" + "00" * 7)


def test_frame_checksum_matches_golden():
    frame = bytes.fromhex(GOLDEN_HEX)
    payload = frame[4:-2]
    assert FcBleMessage.frame_checksum(frame[1], len(frame), payload) == frame[-2]


def test_decrypt_with_bluetoothkey_raw_bytes():
    frame = bytes.fromhex(GOLDEN_HEX)
    inner = ble_decrypt(DEFAULT_BLE_KEY, frame[4:-2])
    assert inner == GOLDEN_INNER
    # inner: len=9, index=2, cat=0xF0, cmd=0x30, xor=0xCB
    assert inner[0] == 9
    assert struct.unpack("<I", inner[2:6])[0] == 2
    assert inner[6] == 0xF0
    assert inner[7] == 0x30


def test_android_xor_variant():
    # 09^F0^30 = C9; ^ index bytes (02 00 00 00) = CB — the captured xor
    msg = FcBleMessage(2, 0xF0, 0x30, b"", xor_variant=XOR_ANDROID)
    assert msg.data_xor() == 0xCB
    msg_js = FcBleMessage(2, 0xF0, 0x30, b"")
    assert msg_js.data_xor() == 0xC9


def test_full_frame_rebuild_is_byte_identical():
    frame = bytes.fromhex(GOLDEN_HEX)
    msg = FcBleMessage(2, 0xF0, 0x30, b"", xor_variant=XOR_ANDROID)
    assert msg.to_frame(DEFAULT_BLE_KEY, pid=0xFF) == frame


def test_parser_roundtrip_fragmented():
    parser = FcBleFrameParser(DEFAULT_BLE_KEY)
    frame = bytes.fromhex(GOLDEN_HEX)
    msgs = parser.feed(frame[:7]) + parser.feed(frame[7:])
    assert len(msgs) == 1
    msg, pid = msgs[0]
    assert pid == 0xFF
    assert msg.index == 2
    assert msg.cmd_category == 0xF0
    assert msg.cmd == 0x30
    assert msg.data == b""


def test_parser_survives_noise():
    parser = FcBleFrameParser(DEFAULT_BLE_KEY)
    msgs = parser.feed(b"\x00\x01\x02" + bytes.fromhex(GOLDEN_HEX))
    assert len(msgs) == 1


def test_parser_drops_corrupt_frame():
    parser = FcBleFrameParser(DEFAULT_BLE_KEY)
    bad = bytearray(bytes.fromhex(GOLDEN_HEX))
    bad[-2] ^= 0x55  # break checksum
    assert parser.feed(bytes(bad)) == []


def test_open_message_shape():
    msg = make_open(index=5)
    inner = msg.to_bytes()
    assert inner[6] == CATEGORY_USER
    assert inner[7] == CMD_USER_REMOTE_UNLOCK
    assert inner[8] == 0x01
    # xor byte included in length
    assert inner[0] == 10  # 9 + 1 data byte


def test_open_with_id_shape():
    msg = make_open_with_id(7, user_id=12)
    inner = msg.to_bytes()
    assert inner[7] == CMD_USER_ID_BLE_OPEN
    assert inner[8:10] == struct.pack("<H", 12)


def test_handshake_payload_layout():
    msg = make_handshake("7b120ba58284f360699d44cebaba0a12", index=1)
    assert len(msg.data) == 39  # 32 lockId + 7 time bytes
    assert msg.data[:32] == b"7b120ba58284f360699d44cebaba0a12"
    inner = msg.to_bytes()
    assert inner[0] == 9 + 39  # LE length incl. xor
    assert inner[2:6] == b"\x01\x00\x00\x00"
    assert inner[6] == CATEGORY_SYSTEM
    assert inner[7] == CMD_SYSTEM_VERIFY_IDENTITY


def test_handshake_response_parse():
    data = (
        bytes([0])
        + bytes.fromhex("4cadb87095639211a1303639d98e9150")  # aeskey 16B
        + b"34:17:27:05:"[:12]
        + b"6.5"
        + b"L5-WIFI-"
        + b"B2.7.3.64"
        + b"\x00\x01"
        + b"fpr-1.0     "
    )
    info = parse_handshake_response(data)
    assert info["result"] == 0
    assert info["aeskey"] == "4cadb87095639211a1303639d98e9150"
    assert info["protocol_version"] == "6.5"
    assert info["firmware"].startswith("B2.7.3")


def test_aes_roundtrip():
    msg = make_open(index=3)
    plain = msg.to_bytes()
    ct = ble_encrypt(DEFAULT_BLE_KEY, plain)
    assert ble_decrypt(DEFAULT_BLE_KEY, ct)[:len(plain)] == plain


if __name__ == "__main__":
    sys.exit(pytest.main([__file__, "-q"]))
