"""Offline verification of the fcble protocol against the golden frame.

Usage:  python tools/ble_test_offline.py

Golden vector: real AES-encrypted BLE frame found inside the official app
bundle (Lock_Controller-4.5.11-*.js, writeBLECharacteristicValue call):
    FD FF 16 00 08 8AAF3DC1ABE8D57CCBB83CAE35C2AF 6B FE
Decrypts (bluetoothKey raw bytes as AES key) to inner message
    09 00 02 00 00 00 F0 30 CB
= len 9, index 2, cat 0xF0 (SPECIAL), cmd 0x30, xor 0xCB
(android xor variant: len ^ cat ^ cmd ^ index bytes = 09^F0^30^02 = CB).
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from fcble import (
    CATEGORY_SPECIAL,
    DEFAULT_BLE_KEY,
    FcBleFrameParser,
    FcBleMessage,
    XOR_ANDROID,
    ble_decrypt,
    ble_encrypt,
)

GOLDEN_HEX = "FDFF1600088AAF3DC1ABE8D57CCBB83CAE35C2AF6BFE"
GOLDEN_INNER = bytes.fromhex("090002000000F030CB" + "00" * 7)  # + zero padding


def main() -> int:
    frame = bytes.fromhex(GOLDEN_HEX)
    payload = frame[4:-2]
    print(f"golden frame:  {frame.hex().upper()}")
    print(f"  pid=0x{frame[1]:02X} len=0x{frame[2] | (frame[3] << 8):04X} "
          f"xor=0x{frame[-2]:02X}")

    # 1) frame checksum
    calc = FcBleMessage.frame_checksum(frame[1], len(frame), payload)
    ok_crc = calc == frame[-2]
    print(f"  frame checksum: ours=0x{calc:02X} {'MATCH' if ok_crc else 'MISMATCH'}")

    # 2) decrypt payload -> inner message
    inner = ble_decrypt(DEFAULT_BLE_KEY, payload)
    ok_aes = inner == GOLDEN_INNER
    print(f"  decrypted inner: {inner.hex().upper()} "
          f"{'== golden' if ok_aes else '!= golden'}")

    # 3) rebuild the exact frame from a parsed message
    from fcble import parse_inner
    msg = parse_inner(inner)
    msg.xor_variant = XOR_ANDROID  # the captured frame uses the native variant
    rebuilt = msg.to_frame(DEFAULT_BLE_KEY, pid=frame[1])
    ok_frame = rebuilt == frame
    print(f"  rebuilt frame:  {rebuilt.hex().upper()} "
          f"{'BYTE-IDENTICAL' if ok_frame else 'DIFFERS'}")
    if not ok_frame:
        print(f"    expected:      {frame.hex().upper()}")

    # 4) parser round-trip (split chunks like BLE MTU)
    parser = FcBleFrameParser(DEFAULT_BLE_KEY)
    msgs = parser.feed(frame[:7]) + parser.feed(frame[7:])
    ok_parse = len(msgs) == 1 and msgs[0][0].cmd == 0x30 and msgs[0][0].index == 2
    print(f"  parser round-trip: {'OK' if ok_parse else 'FAIL'} "
          f"(cat=0x{msgs[0][0].cmd_category:02X} cmd=0x{msgs[0][0].cmd:02X} "
          f"idx={msgs[0][0].index})" if msgs else "  parser: no messages")

    # 5) crypto round-trip of our own handshake message
    from fcble import make_handshake, make_open
    hs = make_handshake("7b120ba58284f360699d44cebaba0a12")
    plain = hs.to_bytes()
    ok_hs_shape = (
        len(hs.data) == 39
        and plain[0] == 9 + 39  # length includes xor byte
        and plain[2:6] == b"\x01\x00\x00\x00"
        and plain[6] == 2 and plain[7] == 8
    )
    roundtrip = ble_decrypt(DEFAULT_BLE_KEY,
                            ble_encrypt(DEFAULT_BLE_KEY, plain))[:len(plain)] == plain
    print(f"  handshake shape: {'OK' if ok_hs_shape else 'BAD'} "
          f"(len={len(hs.data)}, frame={len(hs.to_frame(DEFAULT_BLE_KEY))}B)")
    print(f"  AES round-trip:  {'OK' if roundtrip else 'FAIL'}")

    ok = ok_crc and ok_aes and ok_frame and ok_parse and ok_hs_shape and roundtrip
    print()
    print("RESULT: " + (
        "ALL CHECKS PASSED - protocol implementation reproduces the vendor "
        "app frame byte-for-byte." if ok else "FAILED"))
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
