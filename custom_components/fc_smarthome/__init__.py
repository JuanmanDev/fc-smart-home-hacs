"""FC SmartHome HA integration setup.

One integration, one cloud client, one coordinator, all platforms.
Local BLE is opt-in per entry (options) and augments cloud control.
"""

from __future__ import annotations

import asyncio
import logging
import time

try:  # pragma: no cover - HA environment
    import voluptuous as vol

    from homeassistant.config_entries import ConfigEntry
    from homeassistant.core import HomeAssistant, ServiceCall, SupportsResponse
    from homeassistant.exceptions import ConfigEntryNotReady, HomeAssistantError
    from homeassistant.helpers import config_validation as cv

    _HA_AVAILABLE = True
except ImportError:  # library-only environment (CLI, tests)
    _HA_AVAILABLE = False
    vol = None
    ConfigEntry = HomeAssistant = ServiceCall = SupportsResponse = None
    ConfigEntryNotReady = HomeAssistantError = None
    cv = None

from .api.client import FcClient
from .api.endpoints import EndpointRegistry
from .api.models import LockUserType, TokenPair, parse_ts
from .const import (
    CONF_COUNTRY_CODE,
    CONF_EMAIL,
    CONF_ENDPOINTS_FILE,
    CONF_LOCAL_BLE,
    CONF_LOCAL_LAN,
    CONF_PASSWORD,
    CONF_REGION,
    DOMAIN,
    PLATFORMS,
    SERVICE_ADD_USER,
    SERVICE_BEEP,
    SERVICE_DELETE_USER,
    SERVICE_ENROLL_FINGERPRINT,
    SERVICE_FETCH_HISTORY,
    SERVICE_IMPORT_HISTORY,
    SERVICE_RENAME_USER,
    SERVICE_RING_BELL,
    SERVICE_SET_CHILD_LOCK,
    SERVICE_BLE_UNLOCK,
    SERVICE_BLE_PROBE,
)
from .coordinator import FcCoordinator

_LOGGER = logging.getLogger(__name__)


def _load_protocol_secret(hass, entry, kind: str) -> str | None:
    """Load a protocol secret (secureData / RSA private key).

    Order: config entry data -> environment variable -> secrets file.
    Secrets files are looked up in HA's config directory (recommended:
    `<config>/fc_secure_data.json` and `<config>/fc_app_privkey.b64`) or
    `~/.fcsmarthome/`. Never inside the source tree.
    """
    import json as _json
    import os
    from pathlib import Path

    if entry and entry.data.get(kind):
        return entry.data[kind]
    env_map = {"secure_data": "FC_SECURE_DATA", "private_key": "FC_PRIVATE_KEY_B64"}
    if os.environ.get(env_map.get(kind, "")):
        return os.environ[env_map[kind]]
    names = {
        "secure_data": ("fc_secure_data.json", "secure_data"),
        "private_key": ("fc_app_privkey.b64", None),
    }
    fname, json_key = names[kind]
    candidates = [
        Path(hass.config.config_dir) / fname,
        Path.home() / ".fcsmarthome" / fname,
        Path.cwd() / ".secrets" / fname,
    ]
    for cand in candidates:
        if cand.is_file():
            try:
                if json_key:
                    data = _json.loads(cand.read_text(encoding="utf-8"))
                    if data.get(json_key):
                        return data[json_key]
                else:
                    value = cand.read_text(encoding="utf-8").strip()
                    if value:
                        return value
            except (OSError, ValueError):
                continue
    return None

if _HA_AVAILABLE:
    CONFIG_SCHEMA = vol.Schema({DOMAIN: vol.Schema({})}, extra=vol.ALLOW_EXTRA)
else:
    CONFIG_SCHEMA = None

if _HA_AVAILABLE:
    ADD_USER_SCHEMA = vol.Schema(
        {
            vol.Required("device_id"): cv.string,
            vol.Required("name"): cv.string,
            vol.Required("user_type"): vol.In(
                [t.value for t in LockUserType if t != LockUserType.UNKNOWN]
            ),
            vol.Optional("password"): cv.string,
            vol.Optional("card_id"): cv.string,
        }
    )
    DELETE_USER_SCHEMA = vol.Schema(
        {
            vol.Required("device_id"): cv.string,
            vol.Required("user_id"): cv.string,
        }
    )
    RENAME_USER_SCHEMA = vol.Schema(
        {
            vol.Required("device_id"): cv.string,
            vol.Required("user_id"): cv.string,
            vol.Required("name"): cv.string,
        }
    )
    ENROLL_FINGERPRINT_SCHEMA = vol.Schema(
        {
            vol.Required("device_id"): cv.string,
            vol.Required("name"): cv.string,
        }
    )
    DEVICE_ID_SCHEMA = vol.Schema({vol.Required("device_id"): cv.string})
    CHILD_LOCK_SCHEMA = vol.Schema(
        {
            vol.Required("device_id"): cv.string,
            vol.Required("enabled"): cv.boolean,
        }
    )
else:
    ADD_USER_SCHEMA = DELETE_USER_SCHEMA = RENAME_USER_SCHEMA = None
    ENROLL_FINGERPRINT_SCHEMA = DEVICE_ID_SCHEMA = CHILD_LOCK_SCHEMA = None


async def async_setup_entry(hass: HomeAssistant, entry: ConfigEntry) -> bool:
    """Set up FC SmartHome from a config entry."""
    if not _HA_AVAILABLE:  # pragma: no cover - never happens inside HA
        raise RuntimeError("Home Assistant runtime required")
    hass.data.setdefault(DOMAIN, {})
    endpoints = EndpointRegistry.load(
        entry.data.get(CONF_REGION, "us"),
        entry.data.get(CONF_ENDPOINTS_FILE) or None,
    )

    def _on_token_refreshed(tokens: TokenPair) -> None:
        hass.config_entries.async_update_entry(
            entry,
            data={**entry.data, "tokens": tokens.to_dict()},
        )

    # file I/O must stay off the event loop (HA blocks sync calls in the loop)
    import asyncio as _asyncio

    secure_data = await _asyncio.to_thread(
        _load_protocol_secret, hass, entry, "secure_data"
    )
    private_key_b64 = await _asyncio.to_thread(
        _load_protocol_secret, hass, entry, "private_key"
    )
    if not secure_data or not private_key_b64:
        # the encrypted cloud protocol cannot log in without these
        raise ConfigEntryNotReady(
            "FC SmartHome protocol secrets missing: place fc_secure_data.json "
            "and fc_app_privkey.b64 in the Home Assistant config directory (or "
            "set FC_SECURE_DATA / FC_PRIVATE_KEY_B64), then reload the entry."
        )
    client = FcClient(
        email=entry.data[CONF_EMAIL],
        password=entry.data.get(CONF_PASSWORD, ""),
        region=entry.data.get(CONF_REGION, "us"),
        endpoints=endpoints,
        on_token_refreshed=_on_token_refreshed,
        secure_data=secure_data,
        private_key_b64=private_key_b64,
        country_code=entry.data.get(CONF_COUNTRY_CODE),
    )
    if entry.data.get("tokens"):
        # Restore persisted tokens (family_id etc.), but the negotiated AES
        # session key is ephemeral — a fresh login is always required after
        # a restart. login() renews the token via the cheaper loginToken
        # path first and falls back to a full password login.
        client.tokens = TokenPair.from_dict(entry.data["tokens"])
    try:
        await client.login()
    except Exception as err:  # noqa: BLE001
        if not client.tokens or not client.has_session:
            raise ConfigEntryNotReady(f"FC SmartHome login failed: {err}") from err
        _LOGGER.warning("FC SmartHome login failed; continuing with cached token: %s", err)

    coordinator = FcCoordinator(hass, entry, client)
    await coordinator.async_config_entry_first_refresh()

    # Auto-backfill: when an account is added (first setup) import the
    # full cloud history so sensors/access-log/statistics are complete
    # right away instead of requiring a manual import_history call.
    if not entry.data.get("history_backfilled"):
        entry.async_on_unload(
            hass.async_create_task(_async_backfill_history(hass, entry, coordinator))
        )

    # Local-first transport router (LAN -> BLE -> cloud)
    ble_opt = entry.options.get(CONF_LOCAL_BLE)
    ble_enabled = ble_opt if ble_opt is not None else endpoints.ble.get("enabled", True)
    lan_opt = entry.options.get(CONF_LOCAL_LAN)
    lan_enabled = lan_opt if lan_opt is not None else False

    router = None
    if ble_enabled or lan_enabled:
        router = await _setup_local(
            hass, entry, endpoints, client, coordinator, ble_enabled=ble_enabled
        )

    hass.data[DOMAIN][entry.entry_id] = {
        "client": client,
        "coordinator": coordinator,
        "ble": router.ble_manager if router else None,
        "router": router,
    }

    # Register Home Assistant bluetooth callbacks if BLE is active
    if router and router.ble_manager:
        for device_id, dev in coordinator.devices.items():
            ble_mac = dev.capabilities.get("bleMac") or dev.capabilities.get("mac")
            if ble_mac:
                _setup_ble_callback(hass, entry, coordinator, device_id, ble_mac)

    await hass.config_entries.async_forward_entry_setups(entry, PLATFORMS)
    entry.async_on_unload(entry.add_update_listener(_reload_entry))

    _register_services(hass)
    return True


def _setup_ble_callback(
    hass: HomeAssistant,
    entry: ConfigEntry,
    coordinator: FcCoordinator,
    device_id: str,
    ble_mac: str,
) -> None:
    try:
        from homeassistant.components import bluetooth
        from homeassistant.components.bluetooth import (
            BluetoothCallbackMatcher,
            BluetoothScanningMode,
        )

        def _ble_callback(service_info, change):
            if coordinator.router and coordinator.router.ble_manager and service_info.device:
                coordinator.router.ble_manager.register_discovered_device(
                    ble_mac, service_info.device
                )
            coordinator.handle_ble_advertisement(device_id, service_info)

        entry.async_on_unload(
            bluetooth.async_register_callback(
                hass,
                _ble_callback,
                BluetoothCallbackMatcher(address=ble_mac.upper(), connectable=False),
                BluetoothScanningMode.ACTIVE,
            )
        )
        _LOGGER.info(
            "Registered Home Assistant bluetooth callback for lock %s (%s)",
            device_id,
            ble_mac,
        )
    except Exception as err:
        _LOGGER.debug(
            "Could not register Home Assistant bluetooth callback for %s: %s",
            ble_mac,
            err,
        )


async def _setup_local(
    hass: HomeAssistant,
    entry: ConfigEntry,
    endpoints,
    client,
    coordinator,
    ble_enabled: bool = True,
):
    """Build the local transport router with LAN + BLE channels."""
    try:
        from .local.ble import BleConfig, FcBleManager
        from .local.lan import LanConfig, discover_lan_devices
        from .local.router import FcTransportRouter
    except ImportError as err:
        _LOGGER.warning("Local control unavailable: %s", err)
        return None
    ble_manager = None
    if ble_enabled and endpoints.ble.get("enabled", True):
        ble_manager = FcBleManager(BleConfig.from_registry(endpoints.ble), hass=hass)
        # restore learned protocol versions (v1/v2 dialect per MAC) so the
        # very first unlock after a restart uses the right frames
        await ble_manager.load_versions()

    lan_config = LanConfig.from_registry(endpoints.lan)
    router = FcTransportRouter(client, ble_manager=ble_manager, lan_config=lan_config)
    coordinator.router = router

    # LAN discovery (best-effort, non-blocking on failure)
    if endpoints.lan.get("enabled", True):
        try:
            devices = await discover_lan_devices(timeout=5.0)
            for d in devices:
                _LOGGER.debug("LAN discovery found %s (%s)", d["ip"], d["source"])
            if devices:
                # probe coap on found ips to identify Alink devices
                from .local.lan import probe_coap

                for d in devices:
                    if d["source"] == "udp-broadcast":
                        result = await probe_coap(d["ip"])
                        if result:
                            _LOGGER.info(
                                "Alink device confirmed at %s (code %s)",
                                result["ip"],
                                result["coap_code"],
                            )
        except Exception as err:  # noqa: BLE001
            _LOGGER.debug("LAN discovery skipped: %s", err)

    # Register known BLE MACs from devices
    for device_id, dev in coordinator.devices.items():
        ble_mac = dev.capabilities.get("bleMac") or dev.capabilities.get("mac")
        if ble_mac:
            router.register_ble(device_id, ble_mac)
            if router.ble_manager:
                # VERIFIED from the app bundle: the BLE handshake identity
                # (lockId) is device.deviceBindUserId, NOT the deviceuuid
                # ($plugin.openLock(getBleKey(), getBleMac(), device.deviceBindUserId))
                bind_uid = (
                    dev.raw.get("deviceBindUserId")
                    or dev.capabilities.get("deviceBindUserId")
                )
                if bind_uid:
                    router.ble_manager.register_lock_id(ble_mac, bind_uid)
                else:
                    router.ble_manager.register_lock_id(ble_mac, device_id)

    return router


async def _reload_entry(hass: HomeAssistant, entry: ConfigEntry) -> None:
    await hass.config_entries.async_reload(entry.entry_id)


async def _async_backfill_history(hass: HomeAssistant, entry: ConfigEntry, coordinator) -> None:
    """One-shot full-history import after account add (marks entry when done)."""
    from .api.models import parse_ts

    try:
        for device_id in list(coordinator.devices):
            events = await coordinator.client.get_history(device_id, limit=0, from_ms=0)
            for ev in sorted(events, key=lambda e: e.timestamp or parse_ts(1)):
                coordinator._process_new_events_single(ev)
            coordinator.prime_from_history(device_id, events)
            battery_points = _battery_points(events)
            if battery_points:
                try:
                    _import_battery_stats(hass, device_id, battery_points)
                except Exception as err:  # noqa: BLE001
                    _LOGGER.warning("Battery statistics import failed: %s", err)
        coordinator.async_update_listeners()
        _LOGGER.info("FC SmartHome history backfill complete")
    except Exception as err:  # noqa: BLE001
        _LOGGER.warning("History backfill failed (will retry on next reload): %s", err)
        return
    hass.config_entries.async_update_entry(
        entry, data={**entry.data, "history_backfilled": True}
    )


def _client_for_service(hass: HomeAssistant, device_id: str):
    entry_data = hass.data.get(DOMAIN, {})
    for data in entry_data.values():
        coordinator = data.get("coordinator")
        if coordinator and device_id in coordinator.devices:
            return data["client"], coordinator
    raise HomeAssistantError(f"No FC SmartHome entry owns device {device_id}")


def _battery_points(events) -> list[tuple[float, int]]:
    """Extract (timestamp, battery%) pairs from cloud history events."""
    import re

    points: list[tuple[float, int]] = []
    for ev in events:
        if not ev.timestamp:
            continue
        if "battery" not in (ev.description or "").lower():
            continue
        match = re.search(r"(\d{1,3})\s*%", ev.description or "")
        if match:
            value = int(match.group(1))
            if 0 < value <= 100:
                points.append((ev.timestamp.timestamp(), value))
    return points


def _import_battery_stats(hass: HomeAssistant, device_id: str,
                          points: list[tuple[float, int]]) -> int:
    """Import battery readings as external recorder statistics.

    Statistic id: fc_smarthome:<device8>_battery (add a Statistics graph card
    or read via statistics sensor).
    """
    from datetime import datetime, timezone as dt_timezone

    statistic_id = f"fc_smarthome:{device_id[:8]}_battery"
    metadata = {
        "source": "fc_smarthome",
        "statistic_id": statistic_id,
        "name": f"Smart Lock Battery ({device_id[:8]})",
        "unit_of_measurement": "%",
        "has_mean": True,
        "has_sum": False,
        "mean_type": {  # HA >= 2026.4 requires explicit mean type
            # keep compatible: only set when supported by the running HA
        }.get("type") or "arithmetic",
    }
    # keep one point per hour boundary (recorder convention), newest last
    by_hour: dict[int, list[int]] = {}
    for ts, value in points:
        hour = int(ts // 3600) * 3600
        by_hour.setdefault(hour, []).append(value)
    stats = [
        {
            "start": datetime.fromtimestamp(hour, tz=dt_timezone.utc),
            "mean": sum(vals) / len(vals),
            "sum": None,
        }
        for hour, vals in sorted(by_hour.items())
    ]
    if not stats:
        return 0
    try:
        from homeassistant.components.recorder.statistics import async_add_external_statistics
        async_add_external_statistics(hass, metadata, stats)
        return len(stats)
    except Exception as err:
        _LOGGER.warning("Could not record external battery statistics: %s", err)
        return 0


def _register_services(hass: HomeAssistant) -> None:
    if not hass.services.has_service(DOMAIN, SERVICE_FETCH_HISTORY):

        async def _fetch_history(call: ServiceCall):
            client, coordinator = _client_for_service(hass, call.data["device_id"])
            device_id = call.data["device_id"]
            entries = []
            if coordinator.router and coordinator.router.ble_manager:
                try:
                    entries = await coordinator.async_sync_ble_records(device_id)
                except Exception as err:
                    _LOGGER.debug("BLE history sync failed: %s", err)
            if not entries:
                try:
                    events = await client.get_history(device_id, limit=100)
                    entries = [ev.to_dict() for ev in events]
                    for ev in events:
                        coordinator._process_new_events_single(ev)
                except Exception as err:
                    _LOGGER.debug("Cloud history fetch failed: %s", err)
            return {"entries": entries}

        hass.services.async_register(
            DOMAIN, SERVICE_FETCH_HISTORY, _fetch_history, supports_response=SupportsResponse.OPTIONAL
        )

    if not hass.services.has_service(DOMAIN, SERVICE_IMPORT_HISTORY):

        async def _import_history(call: ServiceCall):
            """Backfill the lock's cloud history into Home Assistant.

            - full access log into the coordinator (last_unlock_* sensors,
               access-log attributes, event feed)
            - battery readings into recorder statistics so the battery
              sensor keeps long-term charts
            - optional per-event HA events for automation backfills
            """
            device_id = call.data["device_id"]
            days = int(call.data.get("days") or 0)  # 0 = everything
            client, coordinator = _client_for_service(hass, device_id)

            from_ms: int | None = None
            if days > 0:
                from_ms = int((time.time() - days * 86400) * 1000)
            events = await client.get_history(device_id, limit=0, from_ms=from_ms)

            # replay oldest-first so the access log ends up newest-first
            imported = 0
            for ev in sorted(events, key=lambda e: e.timestamp or parse_ts(1)):
                if coordinator._process_new_events_single(ev):
                    imported += 1

            # derive session state from the fetched window (last unlock,
            # last bell ring, ring count) and persist battery statistics
            coordinator.prime_from_history(device_id, events)

            # battery statistics backfill (recorder import)
            battery_points = _battery_points(events)
            stats_imported = 0
            if battery_points:
                try:
                    stats_imported = _import_battery_stats(hass, device_id, battery_points)
                except Exception as err:
                    _LOGGER.warning("Battery statistics import failed: %s", err)

            coordinator.async_update_listeners()
            return {
                "events_fetched": len(events),
                "events_imported": imported,
                "battery_stats_imported": stats_imported,
            }

        hass.services.async_register(
            DOMAIN,
            SERVICE_IMPORT_HISTORY,
            _import_history,
            schema=vol.Schema(
                {
                    vol.Required("device_id"): cv.string,
                    vol.Optional("days", description="Days to import (0 = all)"): vol.Coerce(int),
                }
            ),
            supports_response=SupportsResponse.OPTIONAL,
        )

    if not hass.services.has_service(DOMAIN, SERVICE_ADD_USER):

        async def _add_user(call: ServiceCall) -> None:
            client, _ = _client_for_service(hass, call.data["device_id"])
            await client.add_user(
                call.data["device_id"],
                call.data["name"],
                LockUserType.coerce(call.data["user_type"]),
                password=call.data.get("password"),
                card_id=call.data.get("card_id"),
            )

        hass.services.async_register(DOMAIN, SERVICE_ADD_USER, _add_user, ADD_USER_SCHEMA)

    if not hass.services.has_service(DOMAIN, SERVICE_DELETE_USER):

        async def _delete_user(call: ServiceCall) -> None:
            client, _ = _client_for_service(hass, call.data["device_id"])
            await client.delete_user(call.data["device_id"], call.data["user_id"])

        hass.services.async_register(DOMAIN, SERVICE_DELETE_USER, _delete_user, DELETE_USER_SCHEMA)

    if not hass.services.has_service(DOMAIN, SERVICE_RENAME_USER):

        async def _rename_user(call: ServiceCall) -> None:
            client, _ = _client_for_service(hass, call.data["device_id"])
            await client.rename_user(call.data["device_id"], call.data["user_id"], call.data["name"])

        hass.services.async_register(DOMAIN, SERVICE_RENAME_USER, _rename_user, RENAME_USER_SCHEMA)

    if not hass.services.has_service(DOMAIN, SERVICE_ENROLL_FINGERPRINT):

        async def _enroll(call: ServiceCall) -> None:
            client, _ = _client_for_service(hass, call.data["device_id"])
            await client.enroll_fingerprint(call.data["device_id"], call.data["name"])

        hass.services.async_register(
            DOMAIN, SERVICE_ENROLL_FINGERPRINT, _enroll, ENROLL_FINGERPRINT_SCHEMA
        )

    if not hass.services.has_service(DOMAIN, SERVICE_RING_BELL):

        async def _ring(call: ServiceCall) -> None:
            client, _ = _client_for_service(hass, call.data["device_id"])
            await client.ring_bell(call.data["device_id"])

        hass.services.async_register(DOMAIN, SERVICE_RING_BELL, _ring, DEVICE_ID_SCHEMA)

    if not hass.services.has_service(DOMAIN, SERVICE_BEEP):

        async def _beep(call: ServiceCall) -> None:
            client, _ = _client_for_service(hass, call.data["device_id"])
            await client.beep(call.data["device_id"])

        hass.services.async_register(DOMAIN, SERVICE_BEEP, _beep, DEVICE_ID_SCHEMA)

    if not hass.services.has_service(DOMAIN, SERVICE_SET_CHILD_LOCK):

        async def _child_lock(call: ServiceCall) -> None:
            client, _ = _client_for_service(hass, call.data["device_id"])
            await client.set_child_lock(call.data["device_id"], call.data["enabled"])

        hass.services.async_register(DOMAIN, SERVICE_SET_CHILD_LOCK, _child_lock, CHILD_LOCK_SCHEMA)

    if not hass.services.has_service(DOMAIN, SERVICE_BLE_PROBE):

        async def _ble_probe(call: ServiceCall) -> None:
            """BLE diagnostic: scan -> GATT -> handshake, NO unlock.

            Runs inside HA so the ESPHome Bluetooth proxies are usable.
            Cycles handshake identity (deviceuuid first) AND frame version
            (v2 FD first, then v1 FC — the L5 may be a v1-class lock per the
            app's advertisement classification) with SHORT per-attempt
            timeouts so the whole battery fits inside the lock's ~60s wake
            window after a keypad touch.
            """
            device_id = call.data["device_id"]
            _, coordinator = _client_for_service(hass, device_id)
            router = coordinator.router
            if not router or not router.ble_manager:
                raise HomeAssistantError(
                    "BLE is not enabled for this entry (enable 'local ble' in "
                    "the integration options)"
                )
            dev = coordinator.devices.get(device_id)
            mac = dev.capabilities.get("bleMac") or dev.capabilities.get("mac") if dev else None
            if mac:
                from .local.router import _normalize_mac as _norm

                mac = _norm(mac)
            raw_uid = (dev.raw.get("uid") if dev else None) or ""
            # VERIFIED from the app's H5 bundle (chunk-d8ca607a @46450): every
            # BLE plugin call passes device.deviceBindUserId as the lockId:
            #   $plugin.openLock(getBleKey(), getBleMac(), m.value.deviceBindUserId, ...)
            # getBleKey() = bluetoothKey, getBleMac() = uid||mac. The 32-byte
            # handshake identity is therefore the deviceBindUserId!
            bind_uid = (
                (dev.raw.get("deviceBindUserId") if dev else None)
                or dev.capabilities.get("deviceBindUserId")
                or ""
            )
            identities = [
                ("deviceBindUserId", bind_uid),
                ("deviceuuid", device_id),
                ("uid", raw_uid),
                ("zeros", "0" * 32),
            ]
            identities = [(n, i) for n, i in identities if i]
            result: dict = {"device_id": device_id, "mac": mac, "attempts": {}}
            try:
                from homeassistant.components import bluetooth

                ble_dev = bluetooth.async_ble_device_from_address(
                    hass, mac, connectable=True
                ) if mac else None
                result["seen_by_proxies"] = bool(ble_dev)
            except Exception as err:  # noqa: BLE001
                result["seen_by_proxies"] = f"error: {err}"

            last_err: Exception | None = None
            for name, ident in identities:
                transport = None
                try:
                    # manager.transport() retries the GATT connect itself
                    transport = await router.ble_manager.transport(mac)
                    result["attempts"][name] = {"gatt": transport.connected}
                    info = await transport.handshake(user_id_str=ident, timeout=6.0, attempts=2)
                    result["attempts"][name]["handshake"] = "OK"
                    result["attempts"][name].update({
                        k: v for k, v in info.items() if k != "session_aes_key"
                    })
                    result["session_key_acquired"] = bool(transport.session_aes_key)
                    result["identity_that_worked"] = name
                    result["protocol_version"] = getattr(transport, "version", "?")
                    break
                except Exception as err:  # noqa: BLE001
                    last_err = err
                    result["attempts"][name] = {"error": str(err)[:200]}
                finally:
                    if transport:
                        try:
                            await transport.disconnect()
                        except Exception:  # noqa: BLE001
                            pass
                    # the lock needs a moment to release the link between
                    # consecutive GATT connections (verified live: back-to-back
                    # connects return empty service tables)
                    await asyncio.sleep(1.0)
                    for key in (mac, mac.upper() if mac else None):
                        if key:
                            router.ble_manager._transports.pop(key, None)
            result["final"] = str(last_err)[:200] if last_err and "identity_that_worked" not in result else "success"
            _LOGGER.info("BLE probe result for %s: %s", device_id, result)
            for line in (f"{k}: {v}" for k, v in result.items()):
                _LOGGER.info("  %s", line)
            hass.async_create_task(
                hass.services.async_call(
                    "persistent_notification",
                    "create",
                    {
                        "title": "FC BLE probe",
                        "message": "\n".join(f"{k}: {v}" for k, v in result.items()),
                        "notification_id": "fc_ble_probe",
                    },
                )
            )

        hass.services.async_register(DOMAIN, SERVICE_BLE_PROBE, _ble_probe, DEVICE_ID_SCHEMA)

    if not hass.services.has_service(DOMAIN, SERVICE_BLE_UNLOCK):

        async def _ble_unlock(call: ServiceCall) -> None:
            """BLE unlock via the ESP32 proxies — THE reliable local path."""
            device_id = call.data["device_id"]
            _, coordinator = _client_for_service(hass, device_id)
            router = coordinator.router
            if not router or not router.ble_manager:
                raise HomeAssistantError("BLE not enabled for this entry")
            dev = coordinator.devices.get(device_id)
            mac = dev.capabilities.get("bleMac") or dev.capabilities.get("mac") if dev else None
            # the handshake identity is deviceBindUserId (verified from
            # the app bundle: every $plugin call passes deviceBindUserId)
            bind_uid = (
                (dev.raw.get("deviceBindUserId") if dev else None)
                or (dev.capabilities.get("deviceBindUserId") if dev else None)
                or device_id
            )
            if mac:
                from .local.router import _normalize_mac as _norm

                mac = _norm(mac)
                router.ble_manager.register_lock_id(mac, bind_uid)
            # manager.transport() retries the GATT connect internally
            transport = await router.ble_manager.transport(mac)
            try:
                await transport.handshake(user_id_str=bind_uid)
                ok = await transport.remote_unlock()
                if not ok:
                    raise HomeAssistantError("BLE unlock command rejected by the lock")
                _LOGGER.info("FC lock %s unlocked via BLE", device_id)
                # Keep connection alive for reuse; manager will reuse if still connected
            except Exception:
                # On error, disconnect to force fresh connection next time
                await transport.disconnect()
                raise

        hass.services.async_register(DOMAIN, SERVICE_BLE_UNLOCK, _ble_unlock, DEVICE_ID_SCHEMA)


async def async_unload_entry(hass: HomeAssistant, entry: ConfigEntry) -> bool:
    unload_ok = await hass.config_entries.async_unload_platforms(entry, PLATFORMS)
    data = hass.data.get(DOMAIN, {}).pop(entry.entry_id, None)
    if data:
        ble = data.get("ble")
        if ble:
            try:
                await ble.close()
            except Exception:  # noqa: BLE001
                pass
        await data["client"].close()
    return unload_ok