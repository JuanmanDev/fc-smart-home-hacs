"""Lock platform: lock/unlock/latch local-first (LAN -> BLE -> cloud).

Degradation is graceful by design:
- BLE present + healthy   -> unlock over BLE (ESP32 proxies), always works
                             even when the lock sleeps (BLE wakes it).
- BLE absent/fails        -> cloud unlock attempt.
- Cloud 682 (lock asleep) -> automatic retries for ~60s while the user may
                             be touching the keypad, then a persistent
                             notification with the "press 4 and #" guidance
                             and a human error message.
"""

from __future__ import annotations

import logging

from homeassistant.components.lock import LockEntity, LockEntityFeature
from homeassistant.exceptions import HomeAssistantError
from homeassistant.helpers.device_registry import DeviceInfo
from homeassistant.helpers.update_coordinator import CoordinatorEntity

from .const import DOMAIN
from .coordinator import FcCoordinator

_LOGGER = logging.getLogger(__name__)

# Cloud 682 retry window: the vendor backend may relay the open while the
# lock stays awake for a few seconds after a keypad touch (user hint says
# "press 4 and #", wake window is ~1 minute per the app's own strings).
CLOUD_RETRY_SECONDS = 60.0
CLOUD_RETRY_INTERVAL = 5.0
WAKE_GUIDANCE = (
    "FC SmartHome could not open the door: the lock is unreachable right now "
    "(it sleeps to save battery). Press '4' and '#' on the keypad (wake mode, "
    "valid for 1 minute) or touch the keypad, then try again. For fully "
    "remote opening, add an ESP32 Bluetooth proxy near the lock."
)


async def async_setup_entry(hass, entry, async_add_entities):
    data = hass.data[DOMAIN][entry.entry_id]
    coordinator = data["coordinator"]
    router = data.get("router")
    entities = [
        FCLock(coordinator, device_id, router)
        for device_id, device in coordinator.devices.items()
        if device.is_lock or device.is_doorbell
    ]
    async_add_entities(entities)


class FCLock(CoordinatorEntity, LockEntity):
    """FC SmartHome lock (or doorbell acting as lock)."""

    _attr_has_entity_name = True
    _attr_name = None
    _attr_code_format = None

    def __init__(
        self, coordinator: FcCoordinator, device_id: str, router=None
    ) -> None:
        super().__init__(coordinator)
        self.device_id = device_id
        self.router = router
        device = coordinator.devices[device_id]
        self._attr_unique_id = f"{device_id}_lock"
        self._attr_device_info = DeviceInfo(
            identifiers={(DOMAIN, device_id)},
            name=device.name,
            manufacturer=device.manufacturer or "Fingerchip",
            model=device.model,
        )
        self._attr_supported_features = LockEntityFeature.OPEN
        # transient command state: while an unlock/lock runs, the entity
        # keeps the REAL state and reports action="opening/unlocking" so
        # the HA UI shows a spinner instead of a fake "unlocked"
        self._busy: str | None = None

    @property
    def available(self) -> bool:
        return self.device_id in self.coordinator.devices

    @property
    def is_locked(self) -> bool | None:
        status = self.coordinator.statuses.get(self.device_id)
        if status is None:
            return None
        return status.is_locked

    @property
    def extra_state_attributes(self) -> dict:
        status = self.coordinator.statuses.get(self.device_id)
        last = self.coordinator.last_event.get(self.device_id)
        attrs: dict = {"device_id": self.device_id}
        if self._busy:
            attrs["action_in_progress"] = self._busy
        if status:
            attrs.update(
                {
                    "battery": status.battery,
                    "door_open": status.door_open,
                    "door_open_long": status.door_open_long,
                    "tamper": status.tamper,
                    "child_lock": status.child_lock,
                    "motor_error": status.motor_error,
                    "latch_open": status.latch_open,
                    "signal_rssi": status.signal,
                }
            )
        # BLE-learned diagnostics (handshake device info when available)
        model = self.coordinator.device_model.get(self.device_id)
        if model:
            attrs["ble_model"] = model
        fw = self.coordinator.device_firmware.get(self.device_id)
        if fw:
            attrs["ble_firmware"] = fw
        if last:
            attrs["last_event"] = last.to_dict()
        return attrs

    # ---------- helpers ----------

    def _ble_available(self) -> bool:
        """True when a BLE path exists for this device (router + manager)."""
        return bool(self.router and getattr(self.router, "ble_manager", None))

    async def _try_ble_unlock(self) -> bool:
        """Attempt a full BLE unlock (connect + handshake + open).

        Returns True on success; False when BLE is unavailable or the
        exchange failed (the lock may be unreachable). Never raises.
        """
        if not self._ble_available():
            return False
        try:
            result = await self.router.unlock(self.device_id)
            if result.success and "BLE" in (result.message or ""):
                return True
            _LOGGER.debug("router unlock did not use BLE (%s)", result.message)
            return False
        except Exception as err:  # noqa: BLE001
            _LOGGER.debug("BLE unlock path failed: %s", err)
            return False

    async def _control(self, cloud_fn, local_fn=None) -> None:
        """Run a lock command: local first (LAN/BLE via router), then cloud.

        Used by async_lock and async_open (latch). async_unlock has its own
        BLE-first flow with the cloud retry window + wake guidance.
        """
        if local_fn is not None:
            try:
                await local_fn()
                return
            except Exception as err:  # noqa: BLE001
                _LOGGER.debug(
                    "local control failed for %s, falling back to cloud: %s",
                    self.device_id, err,
                )
        await cloud_fn()

    async def _notify_wake_guidance(self) -> None:
        """Persistent notification with the 4-and-# guidance."""
        try:
            await self.hass.services.async_call(
                "persistent_notification",
                "create",
                {
                    "title": "FC SmartHome: door not opened",
                    "message": WAKE_GUIDANCE,
                    "notification_id": f"fc_wake_{self.device_id[:8]}",
                },
                blocking=False,
            )
        except Exception:  # noqa: BLE001
            _LOGGER.debug("could not create the wake-guidance notification")

    async def _cloud_unlock_with_retries(self) -> None:
        """Cloud unlock with an automatic retry window + wake guidance."""
        import asyncio
        import time as _time

        last_error: Exception | None = None
        deadline = _time.monotonic() + CLOUD_RETRY_SECONDS
        attempt = 0
        while _time.monotonic() < deadline:
            attempt += 1
            try:
                await self.coordinator.client.unlock(self.device_id, reason="app")
                _LOGGER.info(
                    "cloud unlock succeeded on attempt %d (lock was awake)", attempt
                )
                return
            except Exception as err:  # noqa: BLE001
                last_error = err
                msg = str(err)
                if "682" in msg or "500" in msg:
                    _LOGGER.debug(
                        "cloud unlock attempt %d got the asleep-682; retrying "
                        "for up to %.0fs more (touch the keypad / press 4 and #)",
                        attempt, deadline - _time.monotonic(),
                    )
                    await asyncio.sleep(CLOUD_RETRY_INTERVAL)
                    continue
                raise  # different error: do not mask it
        # retries exhausted — guide the user instead of a cryptic error
        await self._notify_wake_guidance()
        raise HomeAssistantError(WAKE_GUIDANCE) from last_error

    # ---------- HA lock platform ----------

    def _set_busy(self, action: str | None) -> None:
        self._busy = action
        self.async_write_ha_state()

    async def async_lock(self, **kwargs):
        if self._busy:
            raise HomeAssistantError("A lock command is already running")
        self._set_busy("locking")
        try:
            await self._control(
                lambda: self.coordinator.client.lock(self.device_id),
                (lambda: self.router.lock(self.device_id)) if self.router else None,
            )
            await self.coordinator.async_request_refresh()
        finally:
            self._set_busy(None)

    async def async_unlock(self, **kwargs):
        """Open the door. The state stays truthful (locked) while the BLE
        exchange runs — the UI sees action="opening" (spinner) until the
        lock confirms, then a refresh flips the state for real."""
        if self._busy:
            raise HomeAssistantError("A lock command is already running")
        self._set_busy("opening")
        try:
            if self._ble_available():
                # BLE can wake the lock itself — the reliable local path
                if await self._try_ble_unlock():
                    await self.coordinator.async_request_refresh()
                    return
                _LOGGER.info(
                    "BLE unlock unavailable for %s; falling back to cloud",
                    self.device_id,
                )
            await self._cloud_unlock_with_retries()
            await self.coordinator.async_request_refresh()
        finally:
            self._set_busy(None)

    async def async_open(self, **kwargs):
        """Latch-open = unlock for the L5: BLE not supported for latch and
        the cloud latch endpoint is the same openLock call, so reuse the
        unlock flow (BLE-first, then cloud with the 60s retry window and
        wake guidance instead of a cryptic error)."""
        if self._busy:
            raise HomeAssistantError("A lock command is already running")
        self._set_busy("opening")
        try:
            if self._ble_available():
                if await self._try_ble_unlock():
                    await self.coordinator.async_request_refresh()
                    return
                _LOGGER.info(
                    "BLE open unavailable for %s; falling back to cloud",
                    self.device_id,
                )
            await self._cloud_unlock_with_retries()
            await self.coordinator.async_request_refresh()
        finally:
            self._set_busy(None)
