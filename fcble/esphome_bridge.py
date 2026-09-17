"""Standalone ESPHome BLE bridge — lets a docker-exec script use the ESP32
Bluetooth proxies WITHOUT the HA bluetooth manager.

Reuses the same building blocks HA uses (aioesphomeapi + bleak_esphome):
1. APIClient connects to the ESP32 (host, port, noise_psk)
2. ESPHomeScanner (connect_scanner) gives us advertisement history
3. ESPHomeClient (BleakClient backend) does GATT connect/write/notify
   through the proxy to the FC lock.

Usage inside the HA container:
    python3 /config/python_client/ble_unlock_live.py --phase scan
"""

from __future__ import annotations

import asyncio
import contextlib
import logging
from typing import Optional

from aioesphomeapi import APIClient
from bleak import BleakScanner
from bleak.backends.device import BLEDevice
from bleak.backends.scanner import AdvertisementData

from bleak_esphome import connect_scanner
from bleak_esphome.backend.client import ESPHomeClient, ESPHomeClientData
from bleak_esphome.backend.device import ESPHomeBluetoothDevice

_LOGGER = logging.getLogger(__name__)

# proxies from HA esphome config entries (host, port, noise_psk b64)
PROXIES = {
    "living-cover": ("192.168.2.51", 6053,
                     "iIPMy+rGEAgQ0dGtvBrcQNX7cI5qg9h4Rkz/G8AZZTg="),
    "kitchen": ("192.168.2.50", 6053,
                "ATJHfiF5CWJUzK1bePHKq3Hzoyum52cgiVpA+ZzWTgo="),
}


def _ensure_standalone_manager() -> None:
    """Give habluetooth a manager so bleak_esphome can register scanners.

    In the HA container, get_manager() only works inside the running app.
    For docker-exec scripts we install our own manager first.
    """
    import habluetooth

    try:
        habluetooth.get_manager()
        return  # already set (e.g. inside HA proper)
    except RuntimeError:
        pass
    # minimal no-op adapter backend (we only use remote ESPHome scanners)
    from bluetooth_adapters import BluetoothAdapters

    class _NoAdapters(BluetoothAdapters):
        @property
        def adapters(self) -> dict:
            return {}

        @property
        def default_adapter(self) -> str:
            return "hci0"

    from habluetooth import BluetoothManager, set_manager
    manager = BluetoothManager(_NoAdapters())
    set_manager(manager)


async def _run_manager_setup() -> None:
    """Start the standalone manager (no-op if HA owns it)."""
    import habluetooth

    try:
        manager = habluetooth.get_manager()
    except RuntimeError:
        return
    await manager.async_setup()


async def setup_standalone_bluetooth() -> None:
    """Call once before using ESPHomeProxyBridge outside HA."""
    _ensure_standalone_manager()
    await _run_manager_setup()


class ESPHomeProxyBridge:
    """One ESPHome bluetooth proxy wired for standalone use."""

    def __init__(self, name: str, host: str, port: int, noise_psk: Optional[str] = None):
        self.name = name
        self.host = host
        self.port = port
        self.noise_psk = noise_psk
        self.cli: Optional[APIClient] = None
        self.client_data: Optional[ESPHomeClientData] = None
        self.device: Optional[ESPHomeBluetoothDevice] = None
        self._devices: dict[str, tuple[BLEDevice, AdvertisementData]] = {}

    async def start(self) -> bool:
        self.cli = APIClient(self.host, self.port, "", noise_psk=self.noise_psk)
        try:
            await self.cli.connect()
            device_info = await self.cli.device_info()
        except Exception as err:  # noqa: BLE001
            _LOGGER.warning("proxy %s connect failed: %s", self.name, err)
            return False
        self.client_data = connect_scanner(self.cli, device_info, available=True)
        self.device = self.client_data.bluetooth_device
        scanner = self.client_data.scanner
        setup_cb = scanner.async_setup()
        # async_setup returns a CALLBACK_TYPE (sync unsubscribe), not a coro
        if asyncio.iscoroutine(setup_cb):
            await setup_cb
        if hasattr(scanner, "async_start"):
            res = scanner.async_start()
            if asyncio.iscoroutine(res):
                await res
        _LOGGER.info("proxy %s online (connectable=%s)", self.name,
                     scanner.connectable)
        return True

    @property
    def seen_devices(self) -> dict[str, tuple[BLEDevice, AdvertisementData]]:
        try:
            return dict(
                self.client_data.scanner.discovered_devices_and_advertisement_data
            )
        except Exception:  # noqa: BLE001
            return {}

    async def stop(self) -> None:
        if self.client_data and self.client_data.scanner:
            with contextlib.suppress(Exception):
                await self.client_data.scanner.async_stop()
        if self.cli:
            with contextlib.suppress(Exception):
                await self.cli.disconnect()

    def make_ble_device(self, address: str) -> Optional[BLEDevice]:
        """BLEDevice bound to this proxy for ESPHomeClient."""
        pair = self._devices.get(address)
        if pair:
            return pair[0]
        # synthesize (scanner keeps history; if not seen yet, minimal dev)
        return BLEDevice(address, None, None, -127)

    async def gatt_connect(self, address: str) -> ESPHomeClient:
        dev = self.make_ble_device(address)
        client = ESPHomeClient(dev, client_data=self.client_data)
        await client.connect()
        return client


class MultiProxyBLE:
    """All known proxies; scan and pick the one that sees the lock best."""

    def __init__(self):
        self.bridges: list[ESPHomeProxyBridge] = []

    async def start(self, names: Optional[list[str]] = None) -> list[str]:
        ok = []
        for name, (host, port, psk) in PROXIES.items():
            if names and name not in names:
                continue
            bridge = ESPHomeProxyBridge(name, host, port, psk)
            if await bridge.start():
                self.bridges.append(bridge)
                ok.append(name)
        return ok

    def find_lock(self, address: str) -> Optional[tuple[ESPHomeProxyBridge, int]]:
        best = None
        for b in self.bridges:
            pair = b.seen_devices.get(address)
            if pair:
                rssi = pair[1].rssi or -127
                if not best or rssi > best[1]:
                    best = (b, rssi)
        return best

    async def stop(self) -> None:
        for b in self.bridges:
            try:
                await b.stop()
            except Exception:  # noqa: BLE001
                pass
