"""Event entities: fire HA triggers for every lock/bell/alarm event.

Uses HA's EventEntity contract: calling _trigger_event(event_type, data)
advances the entity's `event` attribute, which the `platform: event` trigger
listens to. One trigger per distinct new access event (dedup by coordinator).
"""

from __future__ import annotations

from collections import deque

from homeassistant.components.event import EventEntity
from homeassistant.helpers.device_registry import DeviceInfo
from homeassistant.helpers.update_coordinator import CoordinatorEntity

from .const import DOMAIN
from .coordinator import FcCoordinator


async def async_setup_entry(hass, entry, async_add_entities):
    coordinator = hass.data[DOMAIN][entry.entry_id]["coordinator"]
    entities = [
        FCEventEntity(coordinator, device_id)
        for device_id, device in coordinator.devices.items()
        if device.is_lock or device.is_doorbell
    ]
    async_add_entities(entities)


class FCEventEntity(CoordinatorEntity, EventEntity):
    """Trigger-capable event entity mirroring every access event."""

    _attr_has_entity_name = True
    _attr_name = "Events"

    def __init__(self, coordinator: FcCoordinator, device_id: str) -> None:
        super().__init__(coordinator)
        self.device_id = device_id
        device = coordinator.devices[device_id]
        self._attr_unique_id = f"{device_id}_events"
        self._attr_device_info = DeviceInfo(
            identifiers={(DOMAIN, device_id)},
            name=device.name,
            manufacturer=device.manufacturer or "Fingerchip",
            model=device.model,
        )
        self._recent: deque = deque(maxlen=50)
        self._last_key: tuple | None = None

    @property
    def event_types(self) -> list[str]:
        return [
            "unlocked",
            "locked",
            "door_open",
            "door_left_open",
            "tamper",
            "low_battery",
            "bell",
            "user_added",
            "user_removed",
            "malfunction",
            "unknown",
        ]

    @property
    def extra_state_attributes(self) -> dict:
        return {
            "recent_events": list(self._recent),
            "access_log_count": len(
                self.coordinator.access_log.get(self.device_id, ())
            ),
        }

    def _handle_coordinator_update(self) -> None:
        log = self.coordinator.access_log.get(self.device_id)
        if log:
            # fire every event newer than the last one we already fired,
            # oldest first (several can arrive in a single poll cycle)
            pending = []
            for entry in log:  # newest-first
                key = (
                    entry.get("event_type"),
                    entry.get("timestamp"),
                    entry.get("user_id"),
                    entry.get("method"),
                )
                if key == self._last_key:
                    break
                pending.append((key, entry))
            if self._last_key is None:
                # first sync after startup: adopt the existing history
                # without replaying old events as new triggers
                if pending:
                    self._last_key = pending[0][0]
                    for _key, entry in pending:
                        self._recent.appendleft(
                            dict(entry, event_type=entry.get("event_type"))
                        )
            else:
                for key, entry in reversed(pending):
                    data = {
                        "device_id": self.device_id,
                        "method": entry.get("method"),
                        "user": entry.get("user"),
                        "user_id": entry.get("user_id"),
                        "remote": entry.get("remote"),
                        "timestamp": entry.get("timestamp"),
                        "description": entry.get("description"),
                    }
                    self._recent.appendleft(
                        dict(data, event_type=entry.get("event_type"))
                    )
                    # advances the `event` attribute -> event-platform triggers
                    self._trigger_event(entry.get("event_type") or "unknown", data)
                if pending:
                    self._last_key = pending[0][0]
        self.async_write_ha_state()
