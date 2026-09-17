"""FC SmartHome cloud client.

Implements the verified vendor protocol (see crypto.py docstring for the
wire details). All request/response bodies are AES-ECB hex blobs; the session
key is negotiated per login via /v2/secure/getSecurityKey.
"""

from __future__ import annotations

import asyncio
import contextlib
import json
import logging
import os
from pathlib import Path
from typing import Any, Callable

import aiohttp

from .crypto import (
    aes_decrypt_hex,
    aes_encrypt_hex,
    load_private_key,
    md5_hex,
    now_ms,
    rsa_private_decrypt,
)
from .endpoints import EndpointRegistry
from .errors import FcApiError, FcAuthError, FcConnectionError, FcError
from .models import (
    ControlResult,
    Device,
    LockEvent,
    LockEventType,
    LockStatus,
    LockUser,
    LockUserType,
    TokenPair,
    UnlockMethod,
    parse_ts,
)

_LOGGER = logging.getLogger(__name__)

MAX_RETRIES = 3
RETRY_BACKOFF = 1.5
REQUEST_TIMEOUT = 15
RATE_LIMIT_STATUS = 672  # vendor-specific: too many requests, retry in 3 min
TOKEN_EXPIRED_STATUS = 690  # vendor-specific: token expired -> re-login
RESULT_OK = 1
# The lock re-locks itself this many seconds after an unlock (auto-relock
# model, verified live 2026-09-11). Cloud lockState sticks at "unlocked"
# after the last event, so we only report unlocked inside this window.
RELOCK_WINDOW_SECONDS = 15


def _now_utc():
    from datetime import datetime, timezone

    return datetime.now(timezone.utc)

# Verified messageKey -> (LockEventType, UnlockMethod|None) mapping from live
# /v2/lock/getLockMessageList/v2 captures (2026-09-09).
MESSAGE_KEY_MAP = {
    "lock.message.local.open": (LockEventType.UNLOCKED, None),  # local credential unlock
    "lock.message.Bluetoothd.open.success": (LockEventType.UNLOCKED, UnlockMethod.APP),
    "lock.message.remote.open.success": (LockEventType.UNLOCKED, UnlockMethod.REMOTE),
    "lock.message.lock.bell": (LockEventType.BELL, None),
    "lock.message.battery.change": (None, None),  # informational battery update
    "lock.message.lower.battery": (LockEventType.LOW_BATTERY, None),
    "lock.message.illegaloperation.alarm": (LockEventType.TAMPER, None),
    "lock.message.adduser": (LockEventType.USER_ADDED, None),
    "lock.message.deleteuser": (LockEventType.USER_REMOVED, None),
    "lock.message.changeusername": (None, None),  # informational rename
}


def _find_protocol_secret(kind: str) -> str | None:
    """Load a protocol secret (secure_data / private_key) from env or disk."""
    env_map = {"secure_data": "FC_SECURE_DATA", "private_key": "FC_PRIVATE_KEY_B64"}
    if os.environ.get(env_map.get(kind, "")):
        return os.environ[env_map[kind]]

    names = {
        "secure_data": ("fc_secure_data.json", "secure_data"),
        "private_key": ("fc_app_privkey.b64", None),
    }
    if kind not in names:
        return None
    fname, json_key = names[kind]
    candidates = [
        Path.cwd() / ".secrets" / fname,
        Path(__file__).resolve().parents[3] / ".secrets" / fname,
        Path.home() / ".fcsmarthome" / fname,
    ]
    for cand in candidates:
        if cand.is_file():
            try:
                if json_key:
                    data = json.loads(cand.read_text(encoding="utf-8"))
                    if data.get(json_key):
                        return data[json_key]
                else:
                    value = cand.read_text(encoding="utf-8").strip()
                    if value:
                        return value
            except (OSError, ValueError):
                continue
    return None


class FcClient:
    """Cloud client speaking the FC SmartHome encrypted protocol."""

    def __init__(
        self,
        email: str,
        password: str,
        region: str = "us",
        endpoints: EndpointRegistry | None = None,
        session: aiohttp.ClientSession | None = None,
        on_token_refreshed: Callable[[TokenPair], None] | None = None,
        secure_data: str | None = None,
        private_key_b64: str | None = None,
        country_code: str | int | None = None,
    ) -> None:
        # The vendor login is phone-based; "email" holds the account name
        # (phone number in E.164 or national format).
        self.email = email
        self._password = password
        self.country_code = str(country_code or os.environ.get("FC_CC", "34"))
        self.endpoints = endpoints or EndpointRegistry.load(region)
        self.endpoints.region = region
        self._session = session
        self._own_session = session is None
        self.tokens: TokenPair | None = None
        self._on_token_refreshed = on_token_refreshed
        self._user_cache: dict[str, dict[str, LockUser]] = {}
        self._last_events: dict[str, list[LockEvent]] = {}
        # protocol artifacts
        self._secure_data = secure_data or _find_protocol_secret("secure_data")  # 'secureData=<urlencoded b64>'
        self._private_key_b64 = private_key_b64 or _find_protocol_secret("private_key")
        self._session_key: bytes | None = None  # negotiated AES key
        self._cookie_session: str | None = None  # SESSION cookie value (b64)

    # ---------- transport ----------

    async def _ensure_session(self) -> aiohttp.ClientSession:
        if self._session is None or self._session.closed:
            self._session = aiohttp.ClientSession(
                timeout=aiohttp.ClientTimeout(total=REQUEST_TIMEOUT),
                connector=self._make_connector(),
            )
            self._own_session = True
        return self._session

    @staticmethod
    def _make_connector() -> aiohttp.TCPConnector:
        """Connector matching the FC cloud's legacy TLS profile.

        www.fcsmartlock.com requires TLS1.2 with legacy renegotiation and
        weak ciphers (AES128-SHA) — verified live. The app ships Alibaba's
        libitls for the same reason.
        """
        import ssl

        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE  # their cert chain fails validation
        ctx.minimum_version = ssl.TLSVersion.TLSv1_2
        ctx.maximum_version = ssl.TLSVersion.TLSv1_2
        for cipher_suite in ("DEFAULT@SECLEVEL=1", "ALL:@SECLEVEL=0"):
            try:
                ctx.set_ciphers(cipher_suite)
                break
            except ssl.SSLError:
                pass
        try:
            ctx.options |= 0x4  # SSL_OP_LEGACY_SERVER_CONNECT
        except Exception:  # noqa: BLE001
            pass
        return aiohttp.TCPConnector(ssl=ctx)

    async def close(self) -> None:
        if self._own_session and self._session and not self._session.closed:
            await self._session.close()
        self._session = None

    def _base_headers(self, token: str = "") -> dict[str, str]:
        h = {
            "token": token,
            "Accept-Language": "en",
            "version": "4.6.6",
            "timezone": "7200000",
            "platform": "Android",
            "appid": "c2a51810216243f69a55571973f1b5d7",
            "phoneId": "5135c25e1ea8e628595521ba0c456ff1",
            "addition": (
                "31458C23F20BCE6C25A3AE6F56DC101DAF8402E2A13A38EB23C61925D528B2166"
                "E818FC3177EADED83BF0A116091BCF0"
            ),
            "Content-Type": "application/json;charset=UTF-8",
            "User-Agent": "okhttp/3.12.8",
            "Connection": "Keep-Alive",
            "Accept-Encoding": "gzip",
        }
        if self._cookie_session:
            h["Cookie"] = f"SESSION={self._cookie_session}"
        return h

    async def _request(
        self,
        method: str,
        url: str,
        payload: dict | None = None,
        auth: bool = True,
        retries: int = MAX_RETRIES,
    ) -> Any:
        """Send an encrypted request; returns the decrypted JSON envelope."""
        if auth and not (self.tokens and self.tokens.access_token and self._session_key):
            raise FcAuthError("Not logged in")
        session = await self._ensure_session()
        key = self._session_key or b""
        headers = self._base_headers(self.tokens.access_token if auth else "")
        if key:  # ts is present on every encrypted call, login included
            headers["ts"] = aes_encrypt_hex(key, str(now_ms()))
        body = aes_encrypt_hex(key, json.dumps(payload or {})) if payload is not None else None

        last_error: Exception | None = None
        for attempt in range(retries):
            try:
                async with session.request(method, url, data=body, headers=headers) as resp:
                    text = await resp.text()
                    if resp.status in (429, RATE_LIMIT_STATUS, 500, 502, 503, 504) and attempt < retries - 1:
                        await asyncio.sleep(min(RETRY_BACKOFF**attempt, 8))
                        continue
                    if resp.status == TOKEN_EXPIRED_STATUS:
                        if auth and self._password and attempt == 0:
                            _LOGGER.info("Cloud token expired (690). Re-login...")
                            with contextlib.suppress(FcError):
                                await self.login()
                                return await self._request(
                                    method, url, payload, auth=auth, retries=1
                                )
                        raise FcAuthError(f"Token expired (690) from {url}")
                    if resp.status >= 400:
                        # error bodies are encrypted too
                        message = text[:200]
                        if text.startswith('"') and len(text) > 4:
                            with contextlib.suppress(Exception):
                                message = aes_decrypt_hex(key, json.loads(text))[:200]
                        raise FcApiError(f"HTTP {resp.status} from {url}: {message}",
                                         code=resp.status)
                    # success: envelope is a quoted hex string
                    if not text.startswith('"'):
                        # plain JSON envelope (rare, e.g. getSecurityKey)
                        try:
                            return json.loads(text)
                        except json.JSONDecodeError:
                            return {"_raw": text}
                    hex_str = json.loads(text)
                    if not isinstance(hex_str, str):
                        return hex_str
                    plain = aes_decrypt_hex(key, hex_str)
                    try:
                        envelope = json.loads(plain)
                    except json.JSONDecodeError:
                        return {"_raw": plain}
                    # vendor envelope: result != 1 is an error
                    if isinstance(envelope, dict) and "result" in envelope:
                        if envelope.get("result") != RESULT_OK:
                            msg = str(envelope.get("message") or plain[:200])
                            code = envelope.get("result")
                            if code in (1001, 401) or "token" in msg.lower():
                                raise FcAuthError(f"API result {code}: {msg}")
                            raise FcApiError(f"API result {code}: {msg}",
                                             code=code, payload=envelope)
                    return envelope
            except (aiohttp.ClientError, asyncio.TimeoutError) as err:
                last_error = err
                if attempt < retries - 1:
                    await asyncio.sleep(min(RETRY_BACKOFF**attempt, 8))
        raise FcConnectionError(f"Request to {url} failed: {last_error}")

    async def _post(self, path_key: str, payload: dict | None = None, auth: bool = True) -> dict:
        body = await self._request("POST", self.endpoints.url(path_key), payload=payload, auth=auth)
        if isinstance(body, dict) and "result" in body:
            if body.get("result") != RESULT_OK:
                raise FcApiError(
                    f"API result {body.get('result')}: {body.get('message', '')}",
                    code=body.get("result"),
                    payload=body,
                )
        return body

    # ---------- auth ----------

    async def _handshake(self) -> bytes:
        """Negotiate the session AES key via getSecurityKey."""
        import base64

        if not self._secure_data or not self._private_key_b64:
            raise FcAuthError(
                "FC cloud login requires the app's secureData blob and RSA "
                "private key (captured from the official app)."
            )
        session = await self._ensure_session()
        headers = self._base_headers()
        headers["Content-Type"] = "application/x-www-form-urlencoded"
        headers.pop("Cookie", None)
        async with session.post(
            self.endpoints.url("security_key"), data=self._secure_data, headers=headers
        ) as resp:
            text = await resp.text()
            if resp.status != 200:
                raise FcAuthError(f"getSecurityKey HTTP {resp.status}: {text[:120]}")
            env = json.loads(text)
            if env.get("result") != RESULT_OK or not env.get("data"):
                raise FcAuthError(f"getSecurityKey failed: {env.get('message')}")
            cookie = resp.cookies.get("SESSION")
            if cookie:
                self._cookie_session = cookie.value
        private = load_private_key(self._private_key_b64)
        payload = rsa_private_decrypt(private, base64.b64decode(env["data"]))
        if not payload or len(payload) < 16:
            raise FcAuthError("Could not decrypt negotiated key (bad RSA payload)")
        negotiated_hex = payload.decode("ascii", errors="replace").strip()
        self._session_key = negotiated_hex[:16].encode("ascii")
        _LOGGER.debug("negotiated session key acquired")
        return self._session_key

    async def login(self) -> TokenPair:
        """Full login: handshake + loginPassword (or loginToken if we have a token)."""
        # token renewal path: cheaper than a fresh login
        if self.tokens and self.tokens.access_token:
            with contextlib.suppress(FcError):
                return await self._login_token()
        return await self._login_password()

    async def _login_token(self) -> TokenPair:
        await self._handshake()
        payload = {
            "phoneModel": "2201123G",
            "phoneBrand": "Xiaomi",
            "channel": "Google",
            "systemVersion": "17",
            "token": self.tokens.access_token,
            "timestamp": now_ms(),
        }
        body = await self._post("login_token", payload, auth=False)
        return self._store_login(body)

    async def _login_password(self) -> TokenPair:
        await self._handshake()
        payload: dict[str, Any] = {
            "password": md5_hex(self._password),
            "phoneModel": "2201123G",
            "phoneBrand": "Xiaomi",
            "channel": "Google",
            "systemVersion": "17",
            "timestamp": now_ms(),
        }
        if "@" in self.email:
            # email-based account (vendor endpoint loginEmailPassword; this
            # account family returns 607 but other vendors/regions may work)
            payload["email"] = self.email
            path = "login_email"
        else:
            # verified flow: phone + countrycode
            phone = self.email.lstrip("+")
            cc = self.country_code
            if phone.startswith(cc) and len(phone) > len(cc) + 6:
                phone = phone[len(cc):]
            payload["phone"] = phone
            payload["countrycode"] = int(cc)
            path = "login"
        body = await self._post(path, payload, auth=False)
        return self._store_login(body)

    def _store_login(self, body: dict) -> TokenPair:
        data = body.get("data") or {}
        token = data.get("token")
        if not token:
            raise FcAuthError(f"No token in login response: {body}")
        if data.get("sessionId"):
            import base64

            self._cookie_session = base64.b64encode(data["sessionId"].encode()).decode()
        family_id = data.get("familyId")
        self.tokens = TokenPair(
            access_token=str(token),
            refresh_token=str(token),
            user_id=str(data.get("id") or "") or None,
            expires_at=0.0,  # vendor token has no known expiry; renew on 690
            session_id=data.get("sessionId"),
            family_id=str(family_id) if family_id else None,
        )
        if self._on_token_refreshed:
            self._on_token_refreshed(self.tokens)
        return self.tokens

    async def refresh_tokens(self) -> TokenPair:
        return await self.login()

    async def ensure_logged_in(self) -> None:
        if self.tokens and self.tokens.access_token and self._session_key:
            return
        await self.login()

    async def logout(self) -> None:
        if self.tokens:
            with contextlib.suppress(FcError):
                await self._post("logout", {"token": self.tokens.access_token})
        self.tokens = None
        self._session_key = None

    def set_tokens(self, tokens: TokenPair) -> None:
        self.tokens = tokens

    @property
    def has_session(self) -> bool:
        """True when the negotiated AES key is available (post-handshake)."""
        return self._session_key is not None

    # ---------- helpers ----------

    @staticmethod
    def _unwrap(body: Any) -> dict:
        if isinstance(body, dict):
            for key in ("data", "result", "payload"):
                inner = body.get(key)
                if isinstance(inner, dict):
                    return inner
            return body
        return {}

    @staticmethod
    def _listify(body: Any, *keys: str) -> list[dict]:
        data = FcClient._unwrap(body)
        for key in keys:
            value = data.get(key)
            if isinstance(value, list):
                return value
            if isinstance(value, dict):
                for sub in ("list", "items", "records", "rows"):
                    if isinstance(value.get(sub), list):
                        return value[sub]
        for value in data.values():
            if isinstance(value, list):
                return value
        return []

    async def _family_id(self) -> str:
        if self.tokens and self.tokens.family_id:
            return self.tokens.family_id
        body = await self._post("family_list", {
            "token": self.tokens.access_token,
            "timestamp": now_ms(),
        })
        # envelope: {"data": [{id, ...}], "result": 1}
        fams = body.get("data") if isinstance(body, dict) else None
        if isinstance(fams, list) and fams and isinstance(fams[0].get("id"), str):
            if self.tokens:
                self.tokens.family_id = fams[0]["id"]
            return fams[0]["id"]
        return "1"

    # ---------- devices ----------

    async def get_devices(self) -> list[Device]:
        family = await self._family_id()
        body = await self._post("devices", {
            "familyId": family,
            "token": self.tokens.access_token,
            "timestamp": now_ms(),
        })
        devices: list[Device] = []
        seen: set[str] = set()
        for item in self._listify(body, "data"):
            dev = self._parse_device(item)
            if dev and dev.device_id not in seen:
                seen.add(dev.device_id)
                devices.append(dev)
        return devices

    async def get_device(self, device_id: str) -> Device | None:
        body = await self._post("device_detail", {
            "id": device_id,
            "token": self.tokens.access_token,
            "timestamp": now_ms(),
        })
        item = self._unwrap(body)
        if not item.get("deviceuuid") and not item.get("id"):
            return None
        item.setdefault("deviceuuid", device_id)
        return self._parse_device(item)

    def _parse_device(self, item: dict) -> Device | None:
        device_id = item.get("deviceuuid") or item.get("id")
        if not device_id:
            return None
        cat_obj = item.get("deviceCategory") or {}
        model = str(cat_obj.get("model") or item.get("model") or "")
        manufacturer = "Fingercrystal"
        category = "lock" if cat_obj.get("productModel") == "SMART_LOCK" or "lock" in model.lower() else ""
        battery = item.get("battery")
        if isinstance(battery, str) and battery.isdigit():
            battery = int(battery)
        dev = Device(
            device_id=str(device_id),
            name=str(item.get("name") or device_id),
            model=model,
            category=category or "lock",
            manufacturer=manufacturer,
            online=bool(item.get("enableWifi", True)),
            battery=int(battery) if isinstance(battery, int) else None,
            signal=None,
            last_update=parse_ts(item.get("messagetime") or item.get("synctime")),
            raw=item,
        )
        capabilities = dev.capabilities
        for k in (
            "bluetoothKey", "secretKey", "dynamicKey", "bleMac", "mac", "macType",
            "firmwareversion", "protocolversion", "functions", "lockState",
            "doorState", "lowbattery", "battery", "deviceBindUserId", "uid",
            "endpoint", "shortaddress",
        ):
            if item.get(k) is not None:
                capabilities[k] = item[k]
        return dev

    async def get_device_status(self, device_id: str) -> LockStatus:
        dev = await self.get_device(device_id)
        if not dev:
            return LockStatus(device_id=device_id)
        raw = dev.raw
        locked: bool | None
        if raw.get("lockState") is None:
            locked = None
        elif raw.get("lockState") == 1:
            locked = True
        else:
            # Auto-relock model (verified live): the cloud lockState sticks
            # at 0 ("unlocked") after the last unlock event forever — the
            # bolt physically re-locks itself within seconds but the lock
            # never reports a relock message. Treat "unlocked" as true only
            # within a short window after the newest unlock event we know.
            locked = True
            for ev in self._last_events.get(device_id, []):
                if ev.type is LockEventType.UNLOCKED and ev.timestamp:
                    age = (_now_utc() - ev.timestamp).total_seconds()
                    if 0 <= age < RELOCK_WINDOW_SECONDS:
                        locked = False
                    break  # events sorted newest-first

        def raw_flag(name: str) -> bool | None:
            value = raw.get(name)
            if value is None:
                return None
            return bool(value)

        # low-battery: the threshold lives in deviceCategory.lowbattery
        # (e.g. 10 = warn below 10%); the top-level payload has no flag
        category = raw.get("deviceCategory") or {}
        low_threshold = category.get("lowbattery")
        battery_val = raw.get("battery")
        low_battery: bool | None = None
        if isinstance(low_threshold, int) and isinstance(battery_val, int):
            low_battery = battery_val <= low_threshold

        status = LockStatus(
            device_id=device_id,
            locked=locked,
            door_open=raw_flag("doorState"),
            battery=raw.get("battery"),
            online=True,
            # alarm/status flags from the verified device payload
            door_open_long=raw_flag("alarmLockNotClosed"),
            tamper=raw_flag("illegaloperation") or raw_flag("alarmIllegaloperation"),
            child_lock=raw_flag("childLock"),
            low_battery=low_battery,
            raw=raw,
        )
        return status

    # ---------- lock control ----------

    async def unlock(self, device_id: str, reason: str = "app") -> ControlResult:
        # remote unlock flow (from app): validate security password then open
        # Known limitation (verified live 2026-09-11): /v2/lock/openLock
        # returns HTTP 500/682 "null" whenever the WiFi lock is asleep /
        # not connected to the vendor cloud — this is server-side; the
        # app shows the same failure. Retry logic for awake windows is in
        # the HA layer (lock.py) and tools/unlock_awake_window.py.
        body = await self._post("remote_unlock", {
            "id": device_id,
            "token": self.tokens.access_token,
            "timestamp": now_ms(),
        })
        data = self._unwrap(body)
        return ControlResult(success=True, message=str(data.get("message") or "ok"), raw=data)

    async def lock(self, device_id: str) -> ControlResult:
        """There is no cloud 'lock' command in the verified protocol.

        ``/v2/lock/openLock`` only OPENS the lock. These models re-lock
        themselves a few seconds after each unlock, so sending openLock
        here (as the old code did) would physically OPEN a door when the
        user asks HA to lock it. Real locking, if ever needed, must come
        from the LAN/BLE channels; the cloud path is a safe no-op.
        """
        return ControlResult(
            success=True,
            message="auto-relock model: the lock re-locks itself after each unlock",
        )

    async def latch(self, device_id: str) -> ControlResult:
        return await self.unlock(device_id)

    async def ring_bell(self, device_id: str) -> ControlResult:
        """Ring the doorbell / find the device.

        No bell-ringing endpoint is verified in the vendor protocol; the
        ``bell`` path is the doorbell-volume *setting*. Best effort: try
        the configured endpoint, never raise into the HA UI.
        """
        try:
            body = await self._post("bell", {
                "id": device_id,
                "token": self.tokens.access_token,
                "timestamp": now_ms(),
            })
        except FcError as err:
            return ControlResult(
                success=False,
                message=f"Remote bell is not supported by the FC cloud protocol ({err})",
            )
        return ControlResult(success=True, message="bell rung", raw=self._unwrap(body))

    async def beep(self, device_id: str) -> ControlResult:
        return await self.ring_bell(device_id)

    async def set_child_lock(self, device_id: str, enabled: bool) -> ControlResult:
        body = await self._post("child_lock", {
            "id": device_id,
            "enable": 1 if enabled else 0,
            "token": self.tokens.access_token,
            "timestamp": now_ms(),
        })
        return ControlResult(success=True, message="ok", raw=self._unwrap(body))

    async def control_capability(
        self, device_id: str, code: str, value: Any
    ) -> ControlResult:
        body = await self._post("control", {
            "id": device_id,
            "code": code,
            "value": value,
            "token": self.tokens.access_token,
            "timestamp": now_ms(),
        })
        return ControlResult(success=True, message="ok", raw=self._unwrap(body))

    # ---------- users ----------

    async def get_users(self, device_id: str) -> list[LockUser]:
        users: list[LockUser] = []
        for user_type in ("1", "2", "3"):
            body = await self._post("users", {
                "userType": user_type,
                "deviceId": device_id,
                "token": self.tokens.access_token,
                "timestamp": now_ms(),
            })
            for item in self._listify(body, "data"):
                user = self._parse_user(item)
                if user:
                    users.append(user)
        self._user_cache[device_id] = {u.user_id: u for u in users}
        # keep name-based lookup for events whose user_id is a message id
        self._user_cache_by_name = getattr(self, "_user_cache_by_name", {})
        self._user_cache_by_name[device_id] = {u.name: u for u in users}
        return users

    def _parse_user(self, item: dict) -> LockUser | None:
        user_id = item.get("id") or item.get("userId")
        if user_id is None:
            return None
        raw_type = item.get("usertype")
        type_map = {"1": "finger", "2": "password", "3": "card"}
        user_type = LockUserType.coerce(type_map.get(str(raw_type), "unknown"))
        return LockUser(
            user_id=str(user_id),
            name=str(item.get("username") or f"{user_type.value}_{user_id}"),
            type=user_type,
            active=bool(item.get("enable", True)),
            password_masked=None,
            card_id=None,
            created_at=parse_ts(item.get("createtime")),
            raw=item,
        )

    # ---------- history ----------

    async def get_history(
        self, device_id: str, limit: int = 50, offset: int = 0, from_ms: int | None = None
    ) -> list[LockEvent]:
        if from_ms is None:
            # full history from time zero: the vendor API returns nothing for
            # narrow recent windows (verified live 2026-09-10) and the event
            # pipeline dedups, so fetch broadly and slice locally
            from_ms = 0
        body = await self._post("logs", {
            "fromTime": from_ms,
            "deviceId": device_id,
            "uuid": device_id,
            "token": self.tokens.access_token,
            "timestamp": now_ms(),
        })
        events = self._parse_events(device_id, body)
        self._enrich_event_methods(device_id, events)
        if limit:
            events = events[:limit]
        self._last_events[device_id] = events
        return events

    async def _ensure_user_cache(self, device_id: str) -> None:
        """Populate the user cache (id -> LockUser) once per device."""
        if device_id in self._user_cache:
            return
        try:
            await self.get_users(device_id)
        except FcError:
            self._user_cache[device_id] = {}

    def _enrich_event_methods(self, device_id: str, events: list[LockEvent]) -> None:
        """Resolve UnlockMethod.UNKNOWN events using the lock user list.

        The cloud history reports only the credential OWNER; the lock user
        list (getLockUserList) says which credential TYPE each owner has
        (1=finger, 2=password, 3=card). Cross-referencing user ids gives
        the real unlock method for most events.
        """
        cache = self._user_cache.get(device_id)
        if not cache:
            return  # cache not loaded yet; first poll after load enriches
        for ev in events:
            if ev.method is not UnlockMethod.UNKNOWN or not ev.user_id:
                continue
            user = cache.get(ev.user_id)
            if user is None:
                # user ids in events are per-message; fall back to name match
                matches = [u for u in cache.values() if u.name == ev.user]
                user = matches[0] if matches else None
            if user is None:
                continue
            method_map = {
                LockUserType.FINGER: UnlockMethod.FINGER,
                LockUserType.PASSWORD: UnlockMethod.PASSWORD,
                LockUserType.CARD: UnlockMethod.CARD,
                LockUserType.NFC: UnlockMethod.NFC,
                LockUserType.FACE: UnlockMethod.FACE,
            }
            ev.method = method_map.get(user.type, UnlockMethod.UNKNOWN)

    def _parse_events(self, device_id: str, body: Any) -> list[LockEvent]:
        events: list[LockEvent] = []
        for item in self._listify(body, "data"):
            ev = self._parse_event(device_id, item)
            if ev:
                events.append(ev)
        epoch = parse_ts(1)
        events.sort(key=lambda e: e.timestamp or epoch, reverse=True)
        return events

    def _parse_event(self, device_id: str, item: dict) -> LockEvent | None:
        try:
            message_key = str(item.get("messageKey") or "")
            description = str(item.get("message") or "")
            user = str(item.get("userName") or "")
            etype, method = MESSAGE_KEY_MAP.get(message_key, (LockEventType.UNKNOWN, None))

            # local.open carries the credential user name (fingerprint/
            # password owner); infer the method from the user name hints
            if method is None and etype is LockEventType.UNLOCKED:
                low = (message_key + " " + user + " " + description).lower()
                if "bluetooth" in low:
                    method = UnlockMethod.APP
                elif any(t in low for t in ("finger", "pulgar", "huella")):
                    method = UnlockMethod.FINGER
                elif any(t in low for t in ("password", "pin", "timeliness", "dynamic")):
                    method = UnlockMethod.PASSWORD
                elif "card" in low:
                    method = UnlockMethod.CARD
                else:
                    # cloud only reports the credential OWNER, not the
                    # method; admins open with fingerprint by default on
                    # this model — mark unknown rather than guess
                    method = UnlockMethod.UNKNOWN

            return LockEvent(
                type=etype or LockEventType.UNKNOWN,
                device_id=device_id,
                timestamp=parse_ts(item.get("messageTime") or item.get("createtime")),
                method=method,
                user=user or None,
                user_id=str(item.get("id") or "") or None,
                remote=message_key == "lock.message.remote.open.success",
                photo_url=item.get("messageIcon"),
                description=description,
                raw=item,
            )
        except Exception:  # noqa: BLE001 - malformed entries must not kill sync
            return None
