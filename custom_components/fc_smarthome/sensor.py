"""Sensor platform: battery, signal, last-event (who/how/when) + access log."""

from __future__ import annotations

from homeassistant.components.sensor import (
    SensorDeviceClass,
    SensorEntity,
    SensorStateClass,
)
from homeassistant.const import EntityCategory
from homeassistant.helpers.device_registry import DeviceInfo
from homeassistant.helpers.update_coordinator import CoordinatorEntity

from .const import DOMAIN
from .coordinator import FcCoordinator


async def async_setup_entry(hass, entry, async_add_entities):
    coordinator = hass.data[DOMAIN][entry.entry_id]["coordinator"]

    entities: list[SensorEntity] = []
    for device_id, device in coordinator.devices.items():
        entities.append(FCLastEventSensor(coordinator, device_id))
        entities.append(FCBatterySensor(coordinator, device_id))
        entities.append(FCSignalSensor(coordinator, device_id))
        entities.append(FCLastUnlockUserSensor(coordinator, device_id))
        entities.append(FCLastUnlockMethodSensor(coordinator, device_id))
        entities.append(FCLastUnlockTimeSensor(coordinator, device_id))
        entities.append(FCDoorbellLastRingSensor(coordinator, device_id))
        entities.append(FCDoorbellRingCountSensor(coordinator, device_id))
        entities.append(FCLastAlarmSensor(coordinator, device_id))
        entities.append(FCLockFirmwareSensor(coordinator, device_id))
        entities.append(FCLockMacSensor(coordinator, device_id))
    async_add_entities(entities)


class FCSensorBase(CoordinatorEntity, SensorEntity):
    _attr_has_entity_name = True

    def __init__(self, coordinator: FcCoordinator, device_id: str, key: str, name: str) -> None:
        super().__init__(coordinator)
        self.device_id = device_id
        device = coordinator.devices[device_id]
        self._attr_unique_id = f"{device_id}_{key}"
        self._attr_name = name
        self._attr_device_info = DeviceInfo(
            identifiers={(DOMAIN, device_id)},
            name=device.name,
            manufacturer=device.manufacturer or "Fingerchip",
            model=device.model,
        )


class FCBatterySensor(FCSensorBase):
    _attr_device_class = SensorDeviceClass.BATTERY
    _attr_state_class = SensorStateClass.MEASUREMENT
    _attr_native_unit_of_measurement = "%"
    _attr_entity_category = EntityCategory.DIAGNOSTIC

    def __init__(self, coordinator: FcCoordinator, device_id: str) -> None:
        super().__init__(coordinator, device_id, "battery", "Battery")

    @property
    def native_value(self) -> int | None:
        status = self.coordinator.statuses.get(self.device_id)
        return status.battery if status else None


class FCSignalSensor(FCSensorBase):
    _attr_state_class = SensorStateClass.MEASUREMENT
    _attr_native_unit_of_measurement = "dBm"
    _attr_entity_category = EntityCategory.DIAGNOSTIC
    _attr_icon = "mdi:signal"

    def __init__(self, coordinator: FcCoordinator, device_id: str) -> None:
        super().__init__(coordinator, device_id, "signal", "Signal")

    @property
    def native_value(self) -> int | None:
        status = self.coordinator.statuses.get(self.device_id)
        return status.signal if status else None


class FCLastEventSensor(FCSensorBase):
    """Who did what last: user + method as state, full log as attributes.

    Every state change is recorded by HA history/logbook, giving a complete
    "who accessed, how, when" timeline per lock.
    """

    _attr_icon = "mdi:history"

    def __init__(self, coordinator: FcCoordinator, device_id: str) -> None:
        super().__init__(coordinator, device_id, "last_event", "Last event")

    @property
    def native_value(self) -> str | None:
        last = self.coordinator.last_event.get(self.device_id)
        if not last:
            return None
        method = last.method.value if last.method else None
        if last.user:
            return f"{last.user} ({method})" if method else last.user
        if method:
            return method
        return last.type.value

    @property
    def extra_state_attributes(self) -> dict:
        last = self.coordinator.last_event.get(self.device_id)
        attrs: dict = {"device_id": self.device_id}
        if last:
            attrs.update(last.to_dict())
        log = self.coordinator.access_log.get(self.device_id)
        if log:
            attrs["access_log"] = list(log)
        return attrs


class FCLastUnlockUserSensor(FCSensorBase):
    _attr_icon = "mdi:account-key"

    def __init__(self, coordinator: FcCoordinator, device_id: str) -> None:
        super().__init__(coordinator, device_id, "last_unlock_user", "Last unlock user")

    @property
    def native_value(self) -> str | None:
        return self.coordinator.last_unlock_user.get(self.device_id)


class FCLastUnlockMethodSensor(FCSensorBase):
    _attr_icon = "mdi:key"

    def __init__(self, coordinator: FcCoordinator, device_id: str) -> None:
        super().__init__(coordinator, device_id, "last_unlock_method", "Last unlock method")

    @property
    def native_value(self) -> str | None:
        return self.coordinator.last_unlock_method.get(self.device_id)


class FCLastUnlockTimeSensor(FCSensorBase):
    _attr_device_class = SensorDeviceClass.TIMESTAMP
    _attr_icon = "mdi:clock-check-outline"

    def __init__(self, coordinator: FcCoordinator, device_id: str) -> None:
        super().__init__(coordinator, device_id, "last_unlock_time", "Last unlock time")

    @property
    def native_value(self):
        return self.coordinator.last_unlock_time.get(self.device_id)


class FCDoorbellLastRingSensor(FCSensorBase):
    _attr_device_class = SensorDeviceClass.TIMESTAMP
    _attr_icon = "mdi:bell-ring-outline"

    def __init__(self, coordinator: FcCoordinator, device_id: str) -> None:
        super().__init__(coordinator, device_id, "doorbell_last_ring", "Last doorbell ring")

    @property
    def native_value(self):
        return self.coordinator.doorbell_last_ring.get(self.device_id)


class FCDoorbellRingCountSensor(FCSensorBase):
    _attr_state_class = SensorStateClass.TOTAL_INCREASING
    _attr_icon = "mdi:counter"

    def __init__(self, coordinator: FcCoordinator, device_id: str) -> None:
        super().__init__(coordinator, device_id, "doorbell_ring_count", "Doorbell ring count")

    @property
    def native_value(self) -> int:
        return self.coordinator.doorbell_ring_count.get(self.device_id, 0)


class FCLastAlarmSensor(FCSensorBase):
    _attr_icon = "mdi:shield-alert-outline"
    _attr_entity_category = EntityCategory.DIAGNOSTIC

    def __init__(self, coordinator: FcCoordinator, device_id: str) -> None:
        super().__init__(coordinator, device_id, "last_alarm", "Last alarm")

    @property
    def native_value(self) -> str | None:
        return self.coordinator.last_alarm.get(self.device_id) or "None"


class FCLockFirmwareSensor(FCSensorBase):
    _attr_icon = "mdi:cellphone-arrow-down"
    _attr_entity_category = EntityCategory.DIAGNOSTIC

    def __init__(self, coordinator: FcCoordinator, device_id: str) -> None:
        super().__init__(coordinator, device_id, "firmware_version", "Firmware version")

    @property
    def native_value(self) -> str | None:
        fw = self.coordinator.device_firmware.get(self.device_id)
        if fw:
            return fw
        dev = self.coordinator.devices.get(self.device_id)
        if not dev:
            return None
        caps = dev.capabilities
        # cloud payload uses lowercase 'firmwareversion'; keep the older
        # spelling as a fallback
        return caps.get("firmwareversion") or caps.get("firmwareVersion")


class FCLockMacSensor(FCSensorBase):
    _attr_icon = "mdi:bluetooth"
    _attr_entity_category = EntityCategory.DIAGNOSTIC

    def __init__(self, coordinator: FcCoordinator, device_id: str) -> None:
        super().__init__(coordinator, device_id, "ble_mac", "Bluetooth MAC")

    @property
    def native_value(self) -> str | None:
        dev = self.coordinator.devices.get(self.device_id)
        if dev:
            return dev.capabilities.get("bleMac") or dev.capabilities.get("mac")
        return None

