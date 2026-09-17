"""Regression tests for the lock entity Open button (async_open).

The 2026-09-17 bug: async_open called the cloud latch directly (openLock)
with no BLE attempt and no asleep-retry window, so with the lock sleeping
the Open button failed with a raw HTTP 682 error while Unlock worked.
The fix mirrors async_unlock: BLE-first, then cloud with a 60 s retry
window and the wake-guidance notification.

homeassistant.* is stubbed so these run without a HA install.
"""

from __future__ import annotations

import asyncio
import sys
import time
import types
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

# ---- stub the homeassistant modules lock.py imports ----
_ha = types.ModuleType("homeassistant")
_components = types.ModuleType("homeassistant.components")
_lock_mod = types.ModuleType("homeassistant.components.lock")


class _Feature(int):
    OPEN = 1


class LockEntity:
    pass


_lock_mod.LockEntity = LockEntity
_lock_mod.LockEntityFeature = _Feature
_exceptions = types.ModuleType("homeassistant.exceptions")


class HomeAssistantError(Exception):
    pass


_exceptions.HomeAssistantError = HomeAssistantError
_helpers = types.ModuleType("homeassistant.helpers")
_dr = types.ModuleType("homeassistant.helpers.device_registry")
_dr.DeviceInfo = dict
_uc = types.ModuleType("homeassistant.helpers.update_coordinator")


class CoordinatorEntity:
    def __init__(self, coordinator):
        self.coordinator = coordinator


_uc.CoordinatorEntity = CoordinatorEntity
_ha.components = _components
sys.modules.setdefault("homeassistant", _ha)
sys.modules.setdefault("homeassistant.components", _components)
sys.modules.setdefault("homeassistant.components.lock", _lock_mod)
sys.modules.setdefault("homeassistant.exceptions", _exceptions)
sys.modules.setdefault("homeassistant.helpers", _helpers)
sys.modules.setdefault("homeassistant.helpers.device_registry", _dr)
sys.modules.setdefault("homeassistant.helpers.update_coordinator", _uc)

from custom_components.fc_smarthome.lock import (  # noqa: E402
    CLOUD_RETRY_INTERVAL,
    FCLock,
    WAKE_GUIDANCE,
)


def _make_lock(ble_available: bool, ble_result: str = "ok") -> tuple[FCLock, dict]:
    """Build an FCLock with mocked coordinator/router and call counters.

    ble_result: "ok" (BLE succeeds), "fail" (BLE raises), "reject"
    (BLE returns success=False).
    """
    coord = MagicMock()
    coord.devices = {"d1": MagicMock()}
    coord.async_request_refresh = AsyncMock()
    coord.client.unlock = AsyncMock(side_effect=Exception("HTTP 682 from openLock: null"))
    coord.client.lock = AsyncMock()
    coord.client.latch = AsyncMock(side_effect=Exception("HTTP 682 from openLock: null"))

    router = MagicMock()
    if ble_available:
        router.ble_manager = MagicMock()
        if ble_result == "ok":
            router.unlock = AsyncMock(return_value=MagicMock(
                success=True, message="unlocked via BLE"))
        elif ble_result == "fail":
            router.unlock = AsyncMock(side_effect=RuntimeError("GATT timeout"))
        else:
            router.unlock = AsyncMock(return_value=MagicMock(
                success=False, message="BLE unlock returned failure"))
        router.latch = AsyncMock()
    else:
        router.ble_manager = None
        router.unlock = AsyncMock()
        router.latch = AsyncMock()

    lock = FCLock.__new__(FCLock)
    lock.coordinator = coord
    lock.router = router
    lock.device_id = "d1"
    lock._busy = None
    lock.async_write_ha_state = lambda: None
    lock.hass = MagicMock()
    lock.hass.services = MagicMock()
    lock.hass.services.async_call = AsyncMock()
    counters = {"client_unlock": coord.client.unlock, "router_unlock": router.unlock,
                "router_latch": router.latch, "client_latch": coord.client.latch}
    return lock, counters


def _short_window(monkeypatch):
    """Shrink the cloud retry window so tests finish fast."""
    import custom_components.fc_smarthome.lock as lock_mod
    monkeypatch.setattr(lock_mod, "CLOUD_RETRY_SECONDS", 0.05)
    monkeypatch.setattr(lock_mod, "CLOUD_RETRY_INTERVAL", 0.01)


@pytest.mark.asyncio
async def test_open_uses_ble_first_when_available(monkeypatch):
    """Open must go through the BLE path (router.unlock) when it exists —
    not the cloud latch that fails with 682 while the lock sleeps."""
    _short_window(monkeypatch)
    lock, counters = _make_lock(ble_available=True)
    await lock.async_open()
    counters["router_unlock"].assert_awaited_once_with("d1")
    counters["router_latch"].assert_not_awaited()
    counters["client_unlock"].assert_not_awaited()
    counters["client_latch"].assert_not_awaited()


@pytest.mark.asyncio
async def test_open_falls_back_to_cloud_with_retries_and_guidance(monkeypatch):
    """Without BLE: cloud retries during the window, then the wake guidance
    (notification + friendly error) instead of a raw HTTP 682 failure."""
    _short_window(monkeypatch)
    lock, counters = _make_lock(ble_available=False)
    with pytest.raises(HomeAssistantError) as exc:
        await lock.async_open()
    assert WAKE_GUIDANCE in str(exc.value)
    assert counters["client_unlock"].await_count >= 2
    counters["client_latch"].assert_not_awaited()
    counters["router_unlock"].assert_not_awaited()
    # guidance notification was created
    lock.hass.services.async_call.assert_awaited()


@pytest.mark.asyncio
async def test_open_does_not_call_cloud_latch_endpoint(monkeypatch):
    """Regression core: the old code called client.latch (openLock, 682) and
    raised immediately. The new flow must never touch client.latch."""
    _short_window(monkeypatch)
    lock, counters = _make_lock(ble_available=True)
    await lock.async_open()
    assert counters["client_latch"].await_count == 0
    assert counters["router_latch"].await_count == 0


@pytest.mark.asyncio
async def test_open_is_reject_while_busy():
    lock, _ = _make_lock(ble_available=False)
    lock._busy = "opening"
    with pytest.raises(HomeAssistantError, match="already running"):
        await lock.async_open()


@pytest.mark.asyncio
async def test_open_ble_present_but_fails_falls_back_to_cloud(monkeypatch):
    """BLE path exists but errors (weak RSSI GATT timeout): async_open must
    degrade to the cloud retry flow with guidance, not surface the BLE
    exception."""
    _short_window(monkeypatch)
    lock, counters = _make_lock(ble_available=True, ble_result="fail")
    with pytest.raises(HomeAssistantError) as exc:
        await lock.async_open()
    assert WAKE_GUIDANCE in str(exc.value)
    counters["client_unlock"].assert_awaited()


@pytest.mark.asyncio
async def test_open_ble_rejects_result_falls_back_to_cloud(monkeypatch):
    """BLE returns success=False (lock did not confirm): same degradation
    contract as a raised error."""
    _short_window(monkeypatch)
    lock, counters = _make_lock(ble_available=True, ble_result="reject")
    with pytest.raises(HomeAssistantError) as exc:
        await lock.async_open()
    assert WAKE_GUIDANCE in str(exc.value)
    counters["client_unlock"].assert_awaited()


def test_retry_constants_match_wake_window():
    """The retry window must cover the ~60 s keypad wake window."""
    import custom_components.fc_smarthome.lock as lock_mod
    assert lock_mod.CLOUD_RETRY_SECONDS >= 55
    assert lock_mod.CLOUD_RETRY_INTERVAL <= 10
