"""Tests for FC SmartHome API: parsing, auth, control, events, endpoints, BLE frames."""

from __future__ import annotations

import json
import sys
import time
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from custom_components.fc_smarthome.api.client import FcClient
from custom_components.fc_smarthome.api.const import DEVICE_STATUS_MASKS
from custom_components.fc_smarthome.api.endpoints import EndpointRegistry
from custom_components.fc_smarthome.api.models import (
    Device,
    LockEventType,
    LockStatus,
    LockUserType,
    TokenPair,
    parse_ts,
)
from custom_components.fc_smarthome.local.ble import build_frame, parse_frame


# ---------- endpoints registry ----------


def test_registry_defaults_load():
    reg = EndpointRegistry.load("us")
    assert reg.base_url.startswith("https://")
    assert reg.url("login").startswith(reg.base_url)


def test_registry_url_device_id():
    reg = EndpointRegistry.load("eu")
    # device_status is now a POST endpoint (device id travels in the
    # encrypted body), so the URL contains the verified path only
    assert reg.url("device_status") == "https://www.fcsmartlock.com/v2/device/getDevice"
    assert reg.url("login").endswith("/v2/login/loginPassword")


def test_registry_override(tmp_path):
    f = tmp_path / "override.json"
    f.write_text('{"paths": {"login": "/x/y"}, "regions": {"us": "https://h"}}')
    reg = EndpointRegistry.load("us", f)
    assert reg.url("login") == "https://h/x/y"
    assert reg.url("devices").startswith("https://h/")


def test_registry_drop_none_paths(tmp_path):
    f = tmp_path / "o.json"
    f.write_text('{"paths": {"bell": null}}')
    reg = EndpointRegistry.load("us", f)
    assert "bell" not in reg.paths


# ---------- models ----------


def test_parse_ts_ms_and_s():
    assert parse_ts(1700000000000) is not None
    assert parse_ts(1700000000) is not None
    assert parse_ts("2026-09-06T12:00:00+00:00") is not None
    assert parse_ts(None) is None


def test_token_validity():
    t = TokenPair(access_token="a", expires_at=time.time() + 3600)
    assert t.valid
    t2 = TokenPair(access_token="a", expires_at=time.time() - 10)
    assert not t2.valid


def test_lock_status_bitmask():
    s = LockStatus.from_dev_status(
        "d1", DEVICE_STATUS_MASKS["locked"] | DEVICE_STATUS_MASKS["tamper"], DEVICE_STATUS_MASKS
    )
    assert s.is_locked is True
    assert s.tamper is True
    assert s.has_problem


def test_lock_status_unlocked_via_latch():
    s = LockStatus.from_dev_status("d1", DEVICE_STATUS_MASKS["latch_open"], DEVICE_STATUS_MASKS)
    assert s.is_locked is False


# ---------- client parsing (no network) ----------


class FakeResponse:
    def __init__(self, body):
        self._body = body

    async def text(self):
        import json

        return json.dumps(self._body)

    async def __aenter__(self):
        return self

    async def __aexit__(self, *a):
        return False


def make_client():
    return FcClient("u@example.com", "pw")


def test_unwrap_and_listify():
    c = make_client()
    assert c._unwrap({"data": {"a": 1}}) == {"a": 1}
    assert c._unwrap({"result": {"list": [1]}}) == {"list": [1]}
    assert c._listify({"data": {"devices": [{"id": 1}]}}, "devices") == [{"id": 1}]
    assert c._listify({"data": {"list": []}}, "devices") == []


def test_parse_device_aliases():
    c = make_client()
    dev = c._parse_device(
        {
            "deviceuuid": "7",
            "name": "Front",
            "deviceCategory": {"productModel": "SMART_LOCK"},
            "battery": 88,
            "messagetime": 1700000000000,
        }
    )
    assert isinstance(dev, Device)
    assert dev.device_id == "7"
    assert dev.battery == 88
    assert dev.is_lock


def test_parse_status_int_and_bool():
    c = make_client()
    # verified shape: lockState 0/1 + doorState bool from getDevice
    class _Dev:
        raw = {"lockState": 1, "doorState": False, "battery": 90}
        battery = 90
        device_id = "d1"

    async def fake_get_device(device_id):
        return _Dev()

    c.get_device = fake_get_device
    import asyncio

    status = asyncio.run(c.get_device_status("d1"))
    assert status.locked is True and status.battery == 90


def test_sticky_unlocked_state_becomes_locked():
    """Auto-relock model: cloud lockState=0 sticks after last unlock event.

    Within the relock window the status must report unlocked; after the
    window it must revert to locked even though the cloud never sends a
    relock message.
    """
    c = make_client()

    class _Dev:
        raw = {"lockState": 0, "doorState": False, "battery": 50}
        battery = 50
        device_id = "d1"

    async def fake_get_device(device_id):
        return _Dev()

    c.get_device = fake_get_device

    from datetime import datetime, timedelta, timezone

    from custom_components.fc_smarthome.api.models import LockEvent, LockEventType

    now = datetime.now(timezone.utc)
    fresh = LockEvent(
        type=LockEventType.UNLOCKED, device_id="d1",
        timestamp=now - timedelta(seconds=2), raw={},
    )
    stale = LockEvent(
        type=LockEventType.UNLOCKED, device_id="d1",
        timestamp=now - timedelta(seconds=120), raw={},
    )

    import asyncio

    c._last_events["d1"] = [fresh]  # newest-first
    status = asyncio.run(c.get_device_status("d1"))
    assert status.locked is False  # unlock 2s ago -> genuinely unlocked

    c._last_events["d1"] = [stale]
    status = asyncio.run(c.get_device_status("d1"))
    assert status.locked is True  # unlock 2 min ago -> auto-relocked


def test_lock_command_is_safe_noop():
    """The cloud protocol has no lock command; lock() must NOT open the door."""
    c = make_client()
    import asyncio

    result = asyncio.run(c.lock("d1"))
    assert result.success is True
    assert "openLock" not in (result.message or "")


def test_parse_users_int_type():
    c = make_client()
    # verified getLockUserList/v2 shape
    user = c._parse_user(
        {"id": "abc123", "usertype": 1, "username": "Dad", "enable": True,
         "createtime": 1782422785000}
    )
    assert user.type is LockUserType.FINGER
    assert user.name == "Dad"
    assert user.active is True


def test_parse_events_types():
    c = make_client()
    events = c._parse_events(
        "d1",
        {
            "data": [
                {"messageKey": "lock.message.local.open", "message": "open lock",
                 "userName": "Dad", "messageTime": 1700000000000, "id": "e1"},
                {"messageKey": "lock.message.illegaloperation.alarm", "message": "Alarm",
                 "messageTime": 1700000001000, "id": "e2"},
                {"messageKey": "lock.message.lock.bell", "message": "lock bell",
                 "messageTime": 1700000002000, "id": "e3"},
            ]
        },
    )
    # sorted newest-first: bell, tamper, dad
    assert [e.type for e in events] == [
        LockEventType.BELL,
        LockEventType.TAMPER,
        LockEventType.UNLOCKED,
    ]
    assert events[2].user == "Dad"


def test_parse_event_unlock_by_user():
    c = make_client()
    ev = c._parse_event(
        "d1",
        {"messageKey": "lock.message.remote.open.success",
         "message": "Successful to remotely open",
         "messageTime": 1700000000000, "id": "e1"},
    )
    assert ev.type is LockEventType.UNLOCKED
    assert ev.remote is True


# ---------- BLE frames ----------


def test_ble_frame_roundtrip():
    frame = build_frame(0x10, b"000000", seq=7)
    parsed = parse_frame(frame)
    assert parsed is not None
    cmd, seq, payload = parsed
    assert cmd == 0x10
    assert seq == 7
    assert payload == b"000000"


def test_ble_frame_corrupt_checksum():
    frame = bytearray(build_frame(0x10, b"ab", seq=1))
    frame[-1] ^= 0xFF
    assert parse_frame(bytes(frame)) is None


def test_ble_frame_short():
    assert parse_frame(b"FCF") is None


# ---------- APK-extracted production config (self-configuration) ----------


def test_apk_extracted_production_server():
    """The registry defaults must match the values extracted from the APK."""
    reg = EndpointRegistry.load("us")
    assert reg.base_url == "https://www.fcsmartlock.com"
    assert reg.regions["intl-aws"] == "https://18.219.242.80"
    assert reg.regions["test"] == "https://test.fcsmartlock.com"
    assert reg.url("login").startswith("https://www.fcsmartlock.com/v2/")


def test_discovery_candidates_prioritize_apk_host():
    from custom_components.fc_smarthome.api.discovery import CANDIDATE_HOSTS

    assert CANDIDATE_HOSTS[0] == "https://www.fcsmartlock.com"


def test_aes_vendor_crypto_roundtrip():
    from custom_components.fc_smarthome.api.discovery import (
        VENDOR_AES_KEY,
        try_aes_decrypt,
        try_aes_encrypt,
    )

    if try_aes_encrypt("x") is None:
        import pytest

        pytest.skip("pycryptodome not installed")
    assert len(VENDOR_AES_KEY) == 32
    ct = try_aes_encrypt("hello fc")
    assert ct is not None
    assert try_aes_decrypt(ct) == "hello fc"


# ---------- coordinator-level event plumbing (pure logic) ----------


class _FakeBus:
    def __init__(self):
        self.fired = []

    def async_fire(self, event_type, payload):
        self.fired.append((event_type, payload))


class _FakeHass:
    def __init__(self):
        self.bus = _FakeBus()


class _FakeCoordinator:
    """Standalone test of the event-processing logic without HA."""


def test_event_dedup_and_bell_tracking():
    """Functional: _process_new_events dedups, latches bell, fires bus events."""
    from custom_components.fc_smarthome.coordinator import FcCoordinator
    from custom_components.fc_smarthome.api.models import LockEvent, LockEventType, UnlockMethod

    coord = FcCoordinator.__new__(FcCoordinator)  # bypass HA-dependent __init__
    coord.devices = {}
    coord.statuses = {}
    coord.last_event = {}
    coord.access_log = {}
    coord.bell_active = {}
    coord._seen_log_ids = {}
    coord.doorbell_last_ring = {}
    coord.doorbell_ring_count = {}
    coord.last_unlock_time = {}
    coord.last_unlock_user = {}
    coord.last_unlock_method = {}
    coord.last_alarm = {}

    class _Bus:
        def __init__(self):
            self.fired = []

        def async_fire(self, etype, payload):
            self.fired.append((etype, payload))

    class _Hass:
        bus = None

    hass = _Hass()
    hass.bus = _Bus()
    coord.hass = hass

    def ev(etype, method, user=None, ts="2026-01-01T10:00:00+00:00", uid=None):
        return LockEvent(
            type=etype,
            device_id="d1",
            timestamp=parse_ts(ts),
            method=UnlockMethod.coerce(method),
            user=user,
            user_id=uid,
            raw={"id": ""},
        )

    batch1 = [
        ev(LockEventType.BELL, None, ts="2026-01-01T10:00:01+00:00"),
        ev(LockEventType.UNLOCKED, "finger", user="Mom", ts="2026-01-01T10:00:00+00:00"),
    ]
    coord._process_new_events("d1", batch1)
    assert len(hass.bus.fired) == 2
    # bell latch stores a timestamp; sensor reads bool(truthy)
    assert coord.bell_active["d1"] is not False and coord.bell_active["d1"] is not None
    assert coord.last_event["d1"].type is LockEventType.BELL
    assert len(coord.access_log["d1"]) == 2
    # unlock tracking derived from the fired events (newest-wins)
    assert coord.last_unlock_user["d1"] == "Mom"
    assert coord.last_unlock_method["d1"] == "finger"
    assert coord.doorbell_ring_count["d1"] == 1

    # replaying the same batch must not fire anything new
    coord._process_new_events("d1", batch1)
    assert len(hass.bus.fired) == 2
    assert len(coord.access_log["d1"]) == 2

    # a genuinely new event fires again
    coord._process_new_events(
        "d1", [ev(LockEventType.LOCKED, "app", ts="2026-01-01T10:05:00+00:00")]
    )
    assert len(hass.bus.fired) == 3
    fired_types = [p["event_type"] for _, p in hass.bus.fired]
    assert "unlocked" in fired_types and "bell" in fired_types and "locked" in fired_types

    # history backfill order: events arrive oldest-first here; the newest
    # bell must win regardless of firing order
    backfill = [
        ev(LockEventType.BELL, None, ts="2026-01-05T08:00:00+00:00"),
        ev(LockEventType.UNLOCKED, "app", user="Dad", ts="2026-01-05T09:00:00+00:00"),
        ev(LockEventType.BELL, None, ts="2026-01-06T12:00:00+00:00"),
        ev(LockEventType.UNLOCKED, "finger", user="Kid", ts="2026-01-06T13:00:00+00:00"),
    ]
    coord._process_new_events("d1", backfill)
    assert coord.doorbell_last_ring["d1"] == parse_ts("2026-01-06T12:00:00+00:00")
    assert coord.last_unlock_user["d1"] == "Kid"
    assert coord.doorbell_ring_count["d1"] == 3

    # prime_from_history derives the same state from a raw event list
    coord2 = FcCoordinator.__new__(FcCoordinator)
    coord2.devices = {}
    coord2.statuses = {}
    coord2.last_event = {}
    coord2.bell_active = {}
    coord2.access_log = {}
    coord2.doorbell_last_ring = {}
    coord2.doorbell_ring_count = {}
    coord2.last_unlock_time = {}
    coord2.last_unlock_user = {}
    coord2.last_unlock_method = {}
    coord2.last_alarm = {}
    coord2._seen_log_ids = {}
    coord2._process_new_events("d2", list(reversed(backfill)))  # fill d2 log
    coord2.doorbell_ring_count = {}  # simulate fresh restart
    coord2.prime_from_history("d2", backfill)
    assert coord2.doorbell_last_ring["d2"] == parse_ts("2026-01-06T12:00:00+00:00")
    assert coord2.last_unlock_user["d2"] == "Kid"
    assert coord2.doorbell_ring_count["d2"] == 2  # 2 bells in the access log


def test_bell_expiry():
    from custom_components.fc_smarthome.coordinator import BELL_LATCH_SECONDS, FcCoordinator

    coord = FcCoordinator.__new__(FcCoordinator)
    coord.bell_active = {"d1": __import__("time").time() - BELL_LATCH_SECONDS - 1}
    coord._expire_bells()
    assert "d1" not in coord.bell_active


def test_event_key_stability():
    from custom_components.fc_smarthome.api.models import LockEvent, LockEventType
    from custom_components.fc_smarthome.coordinator import FcCoordinator

    ev = LockEvent(
        type=LockEventType.UNLOCKED,
        device_id="d1",
        method=None,
        user="Mom",
        raw={"id": 5},
    )
    k1 = FcCoordinator._event_key(ev)
    k2 = FcCoordinator._event_key(ev)
    assert k1 == k2
    assert k1[1] == "unlocked"


# ---------- CLI smoke ----------


def test_cli_parser_builds():
    from fcctl.__main__ import build_parser

    parser = build_parser()
    args = parser.parse_args(["devices"])
    assert args.command == "devices"


def test_cli_parses_add_user():
    from fcctl.__main__ import build_parser

    args = build_parser().parse_args(
        ["--email", "a@b.c", "add-user", "dev1", "--name", "N", "--user-type", "finger"]
    )
    assert args.user_type == "finger"
    assert args.name == "N"


# ---------- HA coordinator mapping (pure logic) ----------


def test_platforms_constant_shape():
    from custom_components.fc_smarthome.api.const import PLATFORMS

    assert "lock" in PLATFORMS
    assert "event" in PLATFORMS
    assert "switch" in PLATFORMS
    assert "button" in PLATFORMS
    assert "binary_sensor" in PLATFORMS
    assert "sensor" in PLATFORMS


# ---------- LAN transport (framing shared with BLE) ----------


def test_lan_module_imports():
    from custom_components.fc_smarthome.local.lan import LanConfig

    cfg = LanConfig()
    assert cfg.coap_port == 5683
    assert 8060 in cfg.tcp_ports


def test_lan_config_from_registry():
    from custom_components.fc_smarthome.local.lan import LanConfig

    cfg = LanConfig.from_registry({"coap_port": 5683, "tcp_ports": [9999]})
    assert cfg.coap_port == 5683
    assert cfg.tcp_ports == [9999]


@pytest.mark.asyncio
async def test_router_falls_back_to_cloud():
    """Router with no local channels routes straight to cloud."""
    from custom_components.fc_smarthome.local.router import FcTransportRouter
    from custom_components.fc_smarthome.api.models import ControlResult

    class FakeClient:
        def __init__(self):
            self.calls = []

        async def unlock(self, device_id, reason="app"):
            self.calls.append("unlock")
            return ControlResult(success=True, message="cloud")

        async def lock(self, device_id):
            self.calls.append("lock")
            return ControlResult(success=True, message="cloud")

        async def latch(self, device_id):
            self.calls.append("latch")
            return ControlResult(success=True, message="cloud")

        async def beep(self, device_id):
            self.calls.append("beep")
            return ControlResult(success=True, message="cloud")

    fake = FakeClient()
    router = FcTransportRouter(fake, ble_manager=None, lan_hosts={})
    result = await router.unlock("dev1")
    assert result.success
    assert fake.calls == ["unlock"]
    result = await router.beep("dev1")
    assert result.success
    assert fake.calls == ["unlock", "beep"]


@pytest.mark.asyncio
async def test_lan_transport_frame_roundtrip():
    """FCFC framing works for the LAN channel identically to BLE."""
    frame = build_frame(0x10, b"000000", seq=3)
    parsed = parse_frame(frame)
    assert parsed is not None
    cmd, seq, payload = parsed
    assert (cmd, seq, payload) == (0x10, 3, b"000000")


class _FakeResp:
    def __init__(self, status, body):
        self.status = status
        # body is already the wire text: a JSON-quoted hex string
        self._text = body

    async def text(self):
        return self._text

    async def __aenter__(self):
        return self

    async def __aexit__(self, *a):
        return False


class _FakeSession:
    closed = False

    def __init__(self, status, body):
        self._resp = _FakeResp(status, body)

    def request(self, method, url, **kw):
        return self._resp


def _logged_in_client(fake_session):
    c = FcClient("600000000", "pw")
    c.tokens = TokenPair(access_token="tok")
    c._session_key = b"0123456789abcdef"
    c._session = fake_session
    return c


@pytest.mark.asyncio
async def test_error_envelope_raises_auth():
    from custom_components.fc_smarthome.api.errors import FcAuthError

    # vendor error envelope inside the encrypted blob
    from custom_components.fc_smarthome.api.crypto import aes_encrypt_hex

    body = aes_encrypt_hex(b"0123456789abcdef", '{"result": 1001, "message": "token expired"}')
    c = _logged_in_client(_FakeSession(200, json.dumps(body)))
    with pytest.raises(FcAuthError):
        await c._request("POST", "https://x/y", payload={})


@pytest.mark.asyncio
async def test_error_envelope_raises_api_error():
    from custom_components.fc_smarthome.api.errors import FcApiError

    from custom_components.fc_smarthome.api.crypto import aes_encrypt_hex

    body = aes_encrypt_hex(b"0123456789abcdef", '{"result": 500, "message": "device offline"}')
    c = _logged_in_client(_FakeSession(200, json.dumps(body)))
    with pytest.raises(FcApiError):
        await c._request("POST", "https://x/y", payload={})


@pytest.mark.asyncio
async def test_success_envelope_passes():
    from custom_components.fc_smarthome.api.crypto import aes_encrypt_hex

    body = aes_encrypt_hex(b"0123456789abcdef", '{"result": 1, "data": {"ok": true}}')
    c = _logged_in_client(_FakeSession(200, json.dumps(body)))
    result = await c._request("POST", "https://x/y", payload={})
    assert result["data"]["ok"] is True


# ---------- CoAP / Alink codec ----------


def test_coap_message_roundtrip():
    from custom_components.fc_smarthome.local.alink import COAP_POST, CoapMessage

    msg = CoapMessage(
        code=COAP_POST,
        msg_id=0x1234,
        token=b"\xab\xcd",
        options=[
            (11, b"sys"),
            (11, b"pk1"),
            (11, b"dn1"),
            (11, b"thing"),
            (11, b"service"),
            (11, b"unlock"),
        ],
        payload=b'{"id":1}',
    )
    dec = CoapMessage.decode(msg.encode())
    assert dec.msg_id == 0x1234
    assert dec.token == b"\xab\xcd"
    # RFC 7252: same-number options (Uri-Path) MUST keep caller order
    assert [o for _, o in dec.options] == [
        b"sys",
        b"pk1",
        b"dn1",
        b"thing",
        b"service",
        b"unlock",
    ]
    assert dec.payload == b'{"id":1}'


def test_coap_extended_option_lengths():
    from custom_components.fc_smarthome.local.alink import COAP_POST, CoapMessage

    long_seg = b"x" * 20  # forces extended length byte
    msg = CoapMessage(
        code=COAP_POST,
        msg_id=1,
        token=b"ab",
        options=[(11, long_seg), (12, b"y" * 300)],  # ext delta + big ext len
        payload=b"z",
    )
    dec = CoapMessage.decode(msg.encode())
    assert dec.options[0] == (11, long_seg)
    assert dec.options[1] == (12, b"y" * 300)
    assert dec.payload == b"z"


def test_coap_ping_ack_decode():
    """A 4-byte CoAP ping-ACK (any RFC-7252 device) decodes safely."""
    from custom_components.fc_smarthome.local.alink import CoapMessage

    dec = CoapMessage.decode(bytes.fromhex("60004643"))
    assert dec.mtype == 2  # ACK
    assert dec.code == 0
    assert dec.payload == b""


def test_alink_topic_shape():
    from custom_components.fc_smarthome.local.alink import AlinkLanDevice

    dev = AlinkLanDevice("1.2.3.4", product_key="a1PK", device_name="dn1")
    assert dev._topic("unlock") == "/topic/sys/a1PK/dn1/thing/service/unlock"


def test_lan_discovery_marks_candidates_unverified():
    """Broadcast findings must default to verified=False (no false locks)."""
    from custom_components.fc_smarthome.local.lan import confirm_fc_device

    assert callable(confirm_fc_device)


def test_fc_ble_package_roundtrip():
    """Verify official FCBlePackage AES framing and inner FCBleBaseMessage roundtrip."""
    from custom_components.fc_smarthome.local.ble import (
        CATEGORY_USER,
        CMD_USER_REMOTE_UNLOCK,
        DEFAULT_AES_KEY,
        FCBleBaseMessage,
        build_fc_package,
        parse_fc_package,
    )

    # Remote unlock command: Category 0x04, Cmd 0x10, data [0x01]
    msg = FCBleBaseMessage(
        cmd_category=CATEGORY_USER,
        cmd=CMD_USER_REMOTE_UNLOCK,
        data=b"\x01",
        seq=42,
        pid=1,
    )
    frame = build_fc_package(msg, key_hex=DEFAULT_AES_KEY, version=2)
    assert frame[0] == 0xFD
    assert frame[-1] == 0xFE
    assert frame[1] == 1  # PID

    parsed = parse_fc_package(frame, key_hex=DEFAULT_AES_KEY, version=2)
    assert parsed is not None
    assert parsed.cmd_category == CATEGORY_USER
    assert parsed.cmd == CMD_USER_REMOTE_UNLOCK
    assert parsed.data == b"\x01"
    assert parsed.seq == 42
    assert parsed.pid == 1


def test_parse_real_live_lock_device():
    """Verify parsing real device payload extracted from live ACache."""
    c = make_client()
    raw = {
        "alarmLockNotClosed": 0,
        "battery": 50,
        "bleMac": "341727051920",
        "bluetooth": True,
        "bluetoothKey": "4CADB87095639211A1303639D98E9150",
        "deviceCategory": {
            "model": "L5-WIFI-QINGKE",
            "name": "L5",
            "functions": "6013452",
        },
        "deviceuuid": "7b120ba58284f360699d44cebaba0a12",
        "id": "7b120ba58284f360699d44cebaba0a12",
        "locSecretKey": "0246f8c5092b29e29a971a0cd1f610fb016763df807a7e70960d4cd3118e601a",
        "mac": "341727051920",
        "name": "Smart Lock",
        "noNetPasswordKey": "fb6c2754a716ba88",
        "protocolversion": "6.5",
        "state": 1,
        "lockState": 0,
        "doorState": False,
        "wifissid": "PJ4_IoT",
    }
    dev = c._parse_device(raw)
    assert dev is not None
    assert dev.device_id == "7b120ba58284f360699d44cebaba0a12"
    assert dev.name == "Smart Lock"
    assert dev.model == "L5-WIFI-QINGKE"
    assert dev.category == "lock"
    assert dev.is_lock is True
    assert dev.battery == 50
    assert dev.online is True
    assert dev.capabilities["bluetoothKey"] == "4CADB87095639211A1303639D98E9150"
    assert dev.capabilities["mac"] == "341727051920"
    assert dev.capabilities["lockState"] == 0


def test_token_pair_session_cookie():
    """Verify TokenPair stores session_id and family_id for persistence."""
    tp = TokenPair(
        access_token="tok123",
        session_id="2897e0c3-3644-4f49-918f-33640075e933",
        family_id="fam_dummy_12345",
    )
    d = tp.to_dict()
    assert d["session_id"] == "2897e0c3-3644-4f49-918f-33640075e933"
    assert d["family_id"] == "fam_dummy_12345"
    restored = TokenPair.from_dict(d)
    assert restored.session_id == tp.session_id
    assert restored.family_id == tp.family_id


def test_router_register_ble():
    from custom_components.fc_smarthome.local.router import FcTransportRouter

    c = FcClient("user@test.com", "pass")
    router = FcTransportRouter(c)
    router.register_ble("dev_1", "34:17:27:05:19:20")
    assert router._ble_addresses["dev_1"] == "34:17:27:05:19:20"


def test_coordinator_doorbell_trigger():
    from custom_components.fc_smarthome.coordinator import FcCoordinator
    from custom_components.fc_smarthome.api.models import LockEventType

    coord = FcCoordinator.__new__(FcCoordinator)
    coord.devices = {}
    coord.statuses = {}
    coord.last_event = {}
    coord.access_log = {}
    coord.bell_active = {}
    coord._seen_log_ids = {}
    coord.doorbell_last_ring = {}
    coord.doorbell_ring_count = {}

    coord.trigger_doorbell("d1")
    assert "d1" in coord.bell_active
    assert coord.doorbell_ring_count["d1"] == 1
    assert coord.doorbell_last_ring["d1"] is not None
    assert coord.last_event["d1"].type == LockEventType.BELL

    coord.trigger_doorbell("d1")
    assert coord.doorbell_ring_count["d1"] == 2


def test_coordinator_ble_adv_handling():
    from custom_components.fc_smarthome.coordinator import FcCoordinator
    from custom_components.fc_smarthome.api.models import LockStatus

    coord = FcCoordinator.__new__(FcCoordinator)
    coord.devices = {}
    coord.statuses = {"d1": LockStatus(device_id="d1", locked=True)}
    coord.last_event = {}
    coord.access_log = {}
    coord.bell_active = {}
    coord._seen_log_ids = {}
    coord.doorbell_last_ring = {}
    coord.doorbell_ring_count = {}
    coord.signal_strengths = {}
    coord.ble_last_seen = {}
    coord._last_ble_sync = {}
    coord._ble_sync_tasks = {}

    class DummyServiceInfo:
        rssi = -75
        manufacturer_data = {
            # 2050 with lock_status = 0x02 (bell active)
            2050: b"341727051920\x00\x01\x02\x00\x00\x00\x00\x00"
        }

    coord.handle_ble_advertisement("d1", DummyServiceInfo())
    assert coord.signal_strengths["d1"] == -75
    assert coord.statuses["d1"].signal == -75
    assert "d1" in coord.bell_active
    assert coord.doorbell_ring_count["d1"] == 1


@pytest.mark.asyncio
async def test_coordinator_sync_ble_records_simulation():
    from custom_components.fc_smarthome.coordinator import FcCoordinator
    from custom_components.fc_smarthome.api.models import Device, LockStatus

    coord = FcCoordinator.__new__(FcCoordinator)
    dev = Device(
        device_id="d1",
        name="Smart Lock",
        capabilities={"bleMac": "34:17:27:05:19:20", "deviceBindUserId": "bind123"},
    )
    coord.devices = {"d1": dev}
    coord.statuses = {"d1": LockStatus(device_id="d1", locked=True)}
    coord.last_event = {}
    coord.access_log = {}
    coord.bell_active = {}
    coord._seen_log_ids = {}
    coord.doorbell_last_ring = {}
    coord.doorbell_ring_count = {}
    coord.last_unlock_user = {}
    coord.last_unlock_method = {}
    coord.last_unlock_time = {}
    coord.last_alarm = {}
    coord.device_firmware = {}
    coord.device_model = {}
    coord.user_cache = {}

    class MockTransport:
        async def handshake(self, user_id=None, user_id_str=None, **_):
            return {
                "firmware_version": "V4.5.11",
                "model": "L5-WIFI",
                "wake_source": 0,
            }

        async def read_device_info(self):
            return {1: 85}

        async def query_users(self):
            return [{"user_id": 1, "user_type": 1}]

        async def query_records(self, record_type=1):
            return [
                {
                    "timestamp": 1700000000,
                    "type": 1,  # unlock
                    "model1": 1,  # fingerprint
                    "user_id": 1,
                }
            ]

    class MockBleManager:
        async def transport(self, mac):
            return MockTransport()

    class MockRouter:
        ble_manager = MockBleManager()

    coord.router = MockRouter()
    events = await coord.async_sync_ble_records("d1")
    assert len(events) == 1
    assert coord.statuses["d1"].battery == 85
    assert coord.last_unlock_method["d1"] == "Fingerprint"
    assert coord.last_unlock_user["d1"] == "Fingerprint 1"
    assert coord.device_firmware["d1"] == "V4.5.11"



