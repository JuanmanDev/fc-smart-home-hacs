"""DataUpdateCoordinator for FC SmartHome.

Event-first design:
- every cycle pulls device list + statuses + history deltas
- new history entries fire both the legacy bus event and update the
  EventEntity + last_event sensor immediately
- keeps an in-memory access-log ring buffer per device (who/how/when)
- tracks bell rings (doorbell playing state) for binary_sensor exposure
"""

from __future__ import annotations

import asyncio
import logging
import time
from collections import deque
from datetime import datetime, timedelta, timezone
from typing import Any

try:  # pragma: no cover - HA runtime
    from homeassistant.config_entries import ConfigEntry
    from homeassistant.core import HomeAssistant
    from homeassistant.exceptions import ConfigEntryAuthFailed
    from homeassistant.helpers.update_coordinator import (
        DataUpdateCoordinator,
        UpdateFailed,
    )

    _HA_AVAILABLE = True
except ImportError:  # library-only environment (CLI, tests)
    _HA_AVAILABLE = False
    ConfigEntry = HomeAssistant = None

    class DataUpdateCoordinator:  # type: ignore[no-redef]
        def __init__(self, *args, **kwargs):
            self.hass = kwargs.get("hass")
            self.name = kwargs.get("name")

        def __getattr__(self, item):
            raise RuntimeError("Home Assistant runtime required")

    class UpdateFailed(Exception):  # type: ignore[no-redef]
        pass

    class ConfigEntryAuthFailed(Exception):  # type: ignore[no-redef]
        pass

from .api.client import FcClient
from .api.errors import FcAuthError
from .api.models import Device, LockEvent, LockEventType, LockStatus, UnlockMethod
from .const import DEFAULT_POLL_INTERVAL, EVENT_FC_EVENT

_LOGGER = logging.getLogger(__name__)

ACCESS_LOG_MAX = 200
BELL_LATCH_SECONDS = 30
# history polling window (ms): fetch the last 7 days each cycle — the
# vendor API needs a millis-epoch fromTime (seconds values return the
# full history; verified live 2026-09-11) and the pipeline dedups events
HISTORY_POLL_WINDOW_MS = 7 * 86_400_000


class FcCoordinator(DataUpdateCoordinator):
    """Coordinator keeping device list + statuses + events in memory."""

    def __init__(self, hass: HomeAssistant, entry: ConfigEntry, client: FcClient) -> None:
        self.entry = entry
        self.client = client
        self.devices: dict[str, Device] = {}
        self.statuses: dict[str, LockStatus] = {}
        self.last_event: dict[str, LockEvent | None] = {}
        self.access_log: dict[str, deque[dict]] = {}
        self.bell_active: dict[str, float] = {}
        self._seen_log_ids: dict[str, set] = {}
        self.doorbell_last_ring: dict[str, datetime | None] = {}
        self.doorbell_ring_count: dict[str, int] = {}
        self.signal_strengths: dict[str, int] = {}
        self.last_unlock_user: dict[str, str | None] = {}
        self.last_unlock_method: dict[str, str | None] = {}
        self.last_unlock_time: dict[str, datetime | None] = {}
        self.last_alarm: dict[str, str | None] = {}
        self.ble_last_seen: dict[str, float] = {}
        self.device_firmware: dict[str, str | None] = {}
        self.device_model: dict[str, str | None] = {}
        self.user_cache: dict[str, dict[int, str]] = {}
        self.router: Any | None = None
        self._ble_sync_tasks: dict[str, asyncio.Task] = {}
        self._last_ble_sync: dict[str, float] = {}
        interval = entry.options.get("poll_interval", DEFAULT_POLL_INTERVAL)
        super().__init__(
            hass,
            _LOGGER,
            name="FC SmartHome",
            update_interval=timedelta(seconds=max(15, int(interval))),
        )

    async def _async_update_data(self) -> dict[str, Any]:
        try:
            cloud_auth_failed = False
            devices = []
            try:
                if self.client.tokens and self.client.tokens.valid and self.client.has_session:
                    devices = await self.client.get_devices()
                elif self.client.email and getattr(self.client, "_password", None):
                    try:
                        await self.client.ensure_logged_in()
                        devices = await self.client.get_devices()
                    except FcAuthError as err:
                        _LOGGER.debug("Cloud auth expired/unavailable: %s", err)
                        cloud_auth_failed = True
                else:
                    # tokens restored but no negotiated session key (post-restart)
                    await self.client.login()
                    devices = await self.client.get_devices()
            except FcAuthError as err:
                _LOGGER.debug("Could not fetch devices from cloud (auth): %s", err)
                cloud_auth_failed = True
            except Exception as err:  # noqa: BLE001
                _LOGGER.debug("Could not fetch devices from cloud: %s", err)

            if devices:
                self.devices = {d.device_id: d for d in devices}
            elif not self.devices and self.entry and self.entry.data.get("devices"):
                for dev_dict in self.entry.data["devices"]:
                    d = Device(
                        device_id=dev_dict["device_id"],
                        name=dev_dict.get("name", "Smart Lock"),
                        model=dev_dict.get("model", ""),
                        category=dev_dict.get("category", "lock"),
                        manufacturer=dev_dict.get("manufacturer", "Fingerchip"),
                        online=dev_dict.get("online", True),
                        capabilities=dev_dict.get("capabilities", {}),
                    )
                    self.devices[d.device_id] = d

            for device_id, device in list(self.devices.items()):
                if not cloud_auth_failed:
                    try:
                        # user list once per device: lets get_history enrich
                        # UnlockMethod.UNKNOWN events (cloud only reports the
                        # credential owner; the user list has the type)
                        await self.client._ensure_user_cache(device_id)
                    except FcAuthError:
                        cloud_auth_failed = True
                    except Exception as err:  # noqa: BLE001
                        _LOGGER.debug(
                            "user list fetch failed for %s: %s", device_id, err
                        )
                if not cloud_auth_failed:
                    try:
                        # history first: unlock events feed the auto-relock
                        # window used by get_device_status
                        events = await self.client.get_history(
                            device_id,
                            limit=30,
                            from_ms=int(time.time() * 1000) - HISTORY_POLL_WINDOW_MS,
                        )
                        self._process_new_events(device_id, events)
                    except FcAuthError:
                        cloud_auth_failed = True
                    except Exception:  # noqa: BLE001
                        _LOGGER.debug("history fetch failed for %s", device_id)
                if not cloud_auth_failed:
                    try:
                        self.statuses[device_id] = await self.client.get_device_status(
                            device_id
                        )
                    except FcAuthError:
                        cloud_auth_failed = True
                    except Exception:  # noqa: BLE001
                        _LOGGER.debug("status fetch failed for %s", device_id)
                if device_id not in self.statuses:
                    battery = device.battery if device.battery is not None else 85
                    self.statuses[device_id] = LockStatus(
                        device_id=device_id,
                        locked=True,
                        battery=battery,
                        online=device.online,
                        door_open=False,
                        tamper=False,
                        low_battery=False,
                    )
            return {
                "devices": self.devices,
                "statuses": self.statuses,
                "last_event": self.last_event,
            }
        except FcAuthError as err:
            # platinum: route auth failures into HA's reauth flow
            raise ConfigEntryAuthFailed(f"FC SmartHome auth failed: {err}") from err
        except Exception as err:  # noqa: BLE001
            if self.devices:
                return {
                    "devices": self.devices,
                    "statuses": self.statuses,
                    "last_event": self.last_event,
                }
            raise UpdateFailed(f"FC SmartHome update failed: {err}") from err

    def _expire_bells(self) -> None:
        now = time.time()
        expired = [
            device_id
            for device_id, ts in self.bell_active.items()
            if now - ts > BELL_LATCH_SECONDS
        ]
        for device_id in expired:
            self.bell_active.pop(device_id, None)

    def _process_new_events(self, device_id: str, events: list[LockEvent]) -> None:
        seen = self._seen_log_ids.setdefault(device_id, set())
        log = self.access_log.setdefault(device_id, deque(maxlen=ACCESS_LOG_MAX))
        fresh: list[LockEvent] = []
        for ev in events:
            key = self._event_key(ev)
            if key in seen:
                continue
            seen.add(key)
            fresh.append(ev)
        if not fresh:
            return
        for ev in fresh:
            log.appendleft(ev.to_dict())
        self.last_event[device_id] = fresh[0]
        # fire oldest-first so per-event state tracking (doorbell ring,
        # last unlock) ends up with the NEWEST value as the final write
        for ev in reversed(fresh):
            self._fire_event(ev)
        _LOGGER.debug("fired %d new events for %s", len(fresh), device_id)

    def _process_new_events_single(self, ev: LockEvent) -> bool:
        """Dedup+record+fire one event (used by fetch_history service)."""
        seen = self._seen_log_ids.setdefault(ev.device_id, set())
        key = self._event_key(ev)
        if key in seen:
            return False
        seen.add(key)
        self.access_log.setdefault(ev.device_id, deque(maxlen=ACCESS_LOG_MAX)).appendleft(
            ev.to_dict()
        )
        self.last_event[ev.device_id] = ev
        self._fire_event(ev)
        return True

    @staticmethod
    def _event_key(ev: LockEvent) -> tuple:
        return (
            ev.timestamp.isoformat() if ev.timestamp else "",
            ev.type.value,
            ev.user_id or "",
            ev.method.value if ev.method else "",
            str(ev.raw.get("id", "")),
        )

    def _fire_event(self, ev: LockEvent) -> None:
        device_id = ev.device_id
        payload = {
            "device_id": device_id,
            "device_name": (
                self.devices[device_id].name if device_id in self.devices else device_id
            ),
            "event_type": ev.type.value,
            "method": ev.method.value if ev.method else None,
            "user": ev.user,
            "user_id": ev.user_id,
            "remote": ev.remote,
            "timestamp": ev.timestamp.isoformat() if ev.timestamp else None,
            "description": ev.description,
        }
        if ev.type is LockEventType.BELL:
            now = time.time()
            self.bell_active[device_id] = now
            prev_ring = self.doorbell_last_ring.get(device_id)
            # keep the NEWEST ring timestamp (older events may fire after
            # newer ones during history backfill)
            if prev_ring is None or (ev.timestamp and ev.timestamp > prev_ring):
                self.doorbell_last_ring[device_id] = (
                    ev.timestamp or datetime.now(timezone.utc)
                )
            self.doorbell_ring_count[device_id] = (
                self.doorbell_ring_count.get(device_id, 0) + 1
            )
        if ev.type is LockEventType.UNLOCKED:
            prev_time = self.last_unlock_time.get(device_id)
            if ev.timestamp and (prev_time is None or ev.timestamp > prev_time):
                self.last_unlock_time[device_id] = ev.timestamp
                self.last_unlock_user[device_id] = ev.user or (
                    f"User {ev.user_id}" if ev.user_id else None
                )
                self.last_unlock_method[device_id] = (
                    ev.method.value if ev.method else "unknown"
                )
        hass_obj = self.__dict__.get("hass")
        if hass_obj and hasattr(hass_obj, "bus") and hasattr(hass_obj.bus, "async_fire"):
            hass_obj.bus.async_fire(EVENT_FC_EVENT, payload)

    def trigger_doorbell(self, device_id: str) -> None:
        """Explicitly trigger a doorbell ringing event."""
        now_dt = datetime.now(timezone.utc)
        _LOGGER.info("Doorbell ringing triggered for %s", device_id)
        ev = LockEvent(
            type=LockEventType.BELL,
            device_id=device_id,
            timestamp=now_dt,
            description="Doorbell ringing",
        )
        self._process_new_events_single(ev)
        if _HA_AVAILABLE and "async_update_listeners" in self.__dict__:
            self.async_update_listeners()

    def prime_from_history(self, device_id: str, events: list[LockEvent]) -> None:
        """Derive session-state (last unlock, last bell, ring count) from
        the full cloud history so sensors are correct right after load,
        instead of accumulating them only from events seen this session."""
        unlocks = [e for e in events if e.type is LockEventType.UNLOCKED and e.timestamp]
        bells = [e for e in events if e.type is LockEventType.BELL and e.timestamp]
        if unlocks:
            newest = max(unlocks, key=lambda e: e.timestamp)
            self.last_unlock_time[device_id] = newest.timestamp
            self.last_unlock_user[device_id] = newest.user or (
                f"User {newest.user_id}" if newest.user_id else None
            )
            self.last_unlock_method[device_id] = (
                newest.method.value if newest.method else "unknown"
            )
        if bells:
            newest_bell = max(bells, key=lambda e: e.timestamp)
            prev = self.doorbell_last_ring.get(device_id)
            if prev is None or newest_bell.timestamp > prev:
                self.doorbell_last_ring[device_id] = newest_bell.timestamp
        # count all bells present in the retained access log (covers
        # restarts: the count continues from history instead of resetting)
        log = self.access_log.get(device_id)
        known_bells = sum(
            1 for e in log or [] if e.get("event_type") == LockEventType.BELL.value
        )
        if known_bells > self.doorbell_ring_count.get(device_id, 0):
            self.doorbell_ring_count[device_id] = known_bells

    def handle_ble_advertisement(self, device_id: str, service_info: Any) -> None:
        """Handle incoming BLE advertisement from HA bluetooth scanner."""
        now = time.time()
        last_seen = self.ble_last_seen.get(device_id, 0)
        self.ble_last_seen[device_id] = now

        rssi = getattr(service_info, "rssi", None)
        if rssi is not None:
            self.signal_strengths[device_id] = rssi
            if device_id in self.statuses:
                self.statuses[device_id].signal = rssi

        # Check if this advertisement is stale (e.g. replayed from HA cache on startup)
        adv_time = getattr(service_info, "time", None)
        is_stale = False
        if adv_time is not None:
            age = abs(time.monotonic() - adv_time)
            if age > 10.0:
                is_stale = True
                _LOGGER.debug("Ignoring stale BLE adv for %s (age=%.1fs)", device_id, age)

        mfg = getattr(service_info, "manufacturer_data", {}) or {}
        _LOGGER.info(
            "BLE adv for %s (connectable=%s, rssi=%s): mfg=%s",
            device_id,
            getattr(service_info, "connectable", None),
            rssi,
            {k: v.hex() if hasattr(v, "hex") else v for k, v in mfg.items()},
        )
        data = mfg.get(2050) or mfg.get(0x0802)
        if data and len(data) >= 15:
            lock_status = data[14]
            _LOGGER.info(
                "BLE mfg status for %s: 0x%02x (%d) full=%s",
                device_id,
                lock_status,
                lock_status,
                data.hex(),
            )
            # Check for bell bit in manufacturer data
            if (lock_status & 0x02) or (lock_status & 0x40) or (len(data) > 15 and data[15] == 1):
                self.trigger_doorbell(device_id)

        # Wakeup burst detection: if lock was dormant for > 10s and advertisement is fresh
        if not is_stale:
            was_sleeping = (now - last_seen) > 10.0
            self.async_trigger_ble_sync(device_id, force=was_sleeping)
        if _HA_AVAILABLE and "async_update_listeners" in self.__dict__:
            self.async_update_listeners()

    def async_trigger_ble_sync(self, device_id: str, force: bool = False) -> None:
        """Trigger background BLE synchronization task (throttled)."""
        if not _HA_AVAILABLE or not self.hass:
            return
        now = time.time()
        last = self._last_ble_sync.get(device_id, 0)
        if not force and (now - last) < 3.0:
            return
        task = self._ble_sync_tasks.get(device_id)
        if task and not task.done():
            return
        self._last_ble_sync[device_id] = now
        self._ble_sync_tasks[device_id] = self.hass.async_create_task(
            self.async_sync_ble_records(device_id)
        )

    async def async_sync_ble_records(self, device_id: str) -> list[dict]:
        """Query lock over BLE for records, diagnostics, battery and user info."""
        if not self.router or not self.router.ble_manager:
            _LOGGER.debug("BLE sync skipped: no ble_manager for %s", device_id)
            return []
        dev = self.devices.get(device_id)
        if not dev:
            return []
        ble_mac = dev.capabilities.get("bleMac") or dev.capabilities.get("mac")
        if not ble_mac:
            return []

        _LOGGER.debug("Starting BLE sync for %s (%s)", device_id, ble_mac)
        try:
            transport = await self.router.ble_manager.transport(ble_mac)
            # handshake identity = deviceBindUserId (verified from the app
            # bundle: $plugin.* calls all pass device.deviceBindUserId);
            # fall back to the transport's bound lock_id then deviceuuid
            bind_uid = (
                (dev.raw.get("deviceBindUserId") if dev else None)
                or dev.capabilities.get("deviceBindUserId")
            )
            identity = bind_uid or getattr(transport, "lock_id", None) or device_id
            info = await transport.handshake(user_id_str=identity)
            _LOGGER.debug("BLE handshake success for %s: %s", device_id, info)

            if info.get("firmware_version"):
                self.device_firmware[device_id] = info["firmware_version"]
            if info.get("model"):
                self.device_model[device_id] = info["model"]

            wake_source = info.get("wake_source")
            if wake_source is not None and wake_source != 0:
                _LOGGER.info(
                    "Lock %s wake source: 0x%04x (%d)",
                    device_id,
                    wake_source,
                    wake_source,
                )
                if wake_source == 2 or (wake_source & 0x02):
                    self.trigger_doorbell(device_id)

            # Read device info (battery & firmware diagnostics)
            try:
                dev_info = await transport.read_device_info()
                _LOGGER.debug("BLE device info for %s: %s", device_id, dev_info)
                if dev_info and 1 in dev_info:
                    bat = dev_info[1]
                    if isinstance(bat, int) and 0 <= bat <= 100:
                        if device_id in self.statuses:
                            self.statuses[device_id].battery = bat
                        if device_id in self.devices:
                            self.devices[device_id].battery = bat
            except Exception as err:
                _LOGGER.debug("BLE read_device_info failed for %s: %s", device_id, err)

            # Fetch registered users for friendly names if not cached
            if device_id not in self.user_cache:
                try:
                    users = await transport.query_users()
                    cache = {}
                    for u in users:
                        uid = u.get("user_id")
                        utype = u.get("user_type")
                        type_names = {
                            1: "Fingerprint",
                            2: "Password",
                            3: "Card",
                            6: "Temp Password",
                            12: "Face",
                        }
                        tname = type_names.get(utype, "User")
                        cache[uid] = f"{tname} {uid}"
                    self.user_cache[device_id] = cache
                except Exception as err:
                    _LOGGER.debug("BLE query_users failed for %s: %s", device_id, err)

            # Query unlock & alarm records
            records = await transport.query_records(record_type=1)
            _LOGGER.debug("BLE query_records returned %d records for %s", len(records), device_id)
            events: list[LockEvent] = []
            for r in records:
                ts = r.get("timestamp")
                dt = datetime.fromtimestamp(ts, tz=timezone.utc) if ts else None
                rtype = r.get("type", 1)
                model1 = r.get("model1", 0)
                uid = r.get("user_id", 0)
                user_name = self.user_cache.get(device_id, {}).get(
                    uid, f"User {uid}" if uid else None
                )

                if rtype == 1:  # Unlock
                    method_map = {
                        1: UnlockMethod.FINGER,
                        2: UnlockMethod.PASSWORD,
                        3: UnlockMethod.CARD,
                        4: UnlockMethod.REMOTE,
                        6: UnlockMethod.PASSWORD,
                        7: UnlockMethod.PASSWORD,
                        10: UnlockMethod.APP,
                        12: UnlockMethod.FACE,
                    }
                    method = method_map.get(model1, UnlockMethod.UNKNOWN)
                    method_str = {
                        1: "Fingerprint",
                        2: "Password",
                        3: "Card",
                        4: "Remote",
                        6: "Temp Password",
                        7: "Dynamic Password",
                        10: "Bluetooth App",
                        12: "Face",
                    }.get(model1, "Unlock")

                    desc = f"{user_name or 'User'} unlocked with {method_str}"
                    ev = LockEvent(
                        type=LockEventType.UNLOCKED,
                        device_id=device_id,
                        timestamp=dt,
                        method=method,
                        user=user_name,
                        user_id=str(uid) if uid else None,
                        description=desc,
                        raw=r,
                    )
                    events.append(ev)

                    if dt and (
                        not self.last_unlock_time.get(device_id)
                        or dt > self.last_unlock_time[device_id]
                    ):
                        self.last_unlock_time[device_id] = dt
                        self.last_unlock_user[device_id] = user_name or (
                            f"User {uid}" if uid else None
                        )
                        self.last_unlock_method[device_id] = method_str
                        if device_id in self.statuses:
                            self.statuses[device_id].locked = False

                            async def _relock(d_id=device_id):
                                await asyncio.sleep(10)
                                if d_id in self.statuses:
                                    self.statuses[d_id].locked = True
                                    if _HA_AVAILABLE and "async_update_listeners" in self.__dict__:
                                        self.async_update_listeners()

                            hass_obj = self.__dict__.get("hass")
                            if hass_obj and hasattr(hass_obj, "async_create_task"):
                                hass_obj.async_create_task(_relock())

                elif rtype in (8, 9, 10, 11, 12, 13, 14):  # Alarms
                    alarm_info = {
                        8: ("Password trial alarm (wrong PIN)", LockEventType.MALFUNCTION),
                        9: ("Card trial alarm (wrong card)", LockEventType.MALFUNCTION),
                        10: ("Fingerprint trial alarm (wrong fingerprint)", LockEventType.MALFUNCTION),
                        11: ("Low battery alarm", LockEventType.LOW_BATTERY),
                        12: ("Tamper / Anti-pry alarm", LockEventType.TAMPER),
                        13: ("Factory reset alarm", LockEventType.MALFUNCTION),
                        14: ("Door lock restarted", LockEventType.UNKNOWN),
                    }
                    msg, etype = alarm_info.get(rtype, ("Lock alarm", LockEventType.UNKNOWN))
                    self.last_alarm[device_id] = msg
                    ev = LockEvent(
                        type=etype,
                        device_id=device_id,
                        timestamp=dt,
                        description=msg,
                        raw=r,
                    )
                    events.append(ev)

            if events:
                self._process_new_events(device_id, events)

            if _HA_AVAILABLE and "async_update_listeners" in self.__dict__:
                self.async_update_listeners()
            return [ev.to_dict() for ev in events]
        except Exception as err:
            _LOGGER.warning("BLE sync failed for %s: %s", device_id, err, exc_info=True)
            return []

