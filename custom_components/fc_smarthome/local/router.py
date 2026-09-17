"""Unified transport router: local LAN → local BLE → cloud.

Local-first: if the device is reachable on the LAN (WiFi lock/gateway)
use the LAN channel; else if a BLE address is known use BLE; else fall
back to cloud. Keeps one source of truth for commands, mirrors control
results into the same ControlResult/LockStatus models.
"""

from __future__ import annotations

import logging

from ..api.client import FcClient
from ..api.errors import FcLocalError
from ..api.models import ControlResult, LockStatus
from .ble import FcBleManager, FcBleTransport
from .lan import FcLanTransport, LanConfig

_LOGGER = logging.getLogger(__name__)


def _normalize_mac(address: str) -> str:
    """Cloud payloads use raw hex ('341727051920'); bleak uses
    colon-separated ('34:17:27:05:19:20'). Return the colon form."""
    raw = address.strip().replace(":", "").replace("-", "").upper()
    if len(raw) == 12:
        return ":".join(raw[i:i + 2] for i in range(0, 12, 2))
    return address


class FcTransportRouter:
    """Routes commands to the best available transport for a device.

    Preferences (first available wins):
      1. LAN (WiFi lock or gateway at a known host:port)
      2. BLE (paired lock address)
      3. Cloud (always available when credentials work)
    """

    def __init__(
        self,
        client: FcClient,
        ble_manager: FcBleManager | None = None,
        lan_hosts: dict[str, tuple[str, int]] | None = None,
        lan_config: LanConfig | None = None,
    ) -> None:
        self.client = client
        self.ble_manager = ble_manager
        self.lan_hosts = dict(lan_hosts or {})
        self.lan_config = lan_config or LanConfig()
        self._lan: dict[str, FcLanTransport] = {}
        self._ble_addresses: dict[str, str] = {}

    def register_lan(self, device_id: str, host: str, port: int) -> None:
        """Associate a device id with a LAN endpoint (from discovery)."""
        self.lan_hosts[device_id] = (host, port)

    def register_ble(self, device_id: str, address: str) -> None:
        """Associate a device id with a BLE address (from scan)."""
        if not hasattr(self, "_ble_addresses"):
            self._ble_addresses = {}
        # normalize: cloud payloads carry raw hex (341727051920) while
        # bleak/HA use colon format (34:17:27:05:19:20)
        mac = _normalize_mac(address)
        self._ble_addresses[device_id] = mac
        if self.ble_manager is not None:
            self.ble_manager._discovered.setdefault(mac, None)
            self.ble_manager._discovered.setdefault(mac.upper(), None)
            # keep the handshake identity (cloud lock id) linked to the MAC
            # so the handshake uses the deviceuuid even when the caller
            # passes no explicit identity
            if hasattr(self.ble_manager, "register_lock_id"):
                self.ble_manager.register_lock_id(mac, device_id)

    async def _lan_transport(self, device_id: str) -> FcLanTransport | None:
        endpoint = self.lan_hosts.get(device_id)
        if endpoint is None:
            return None
        host, port = endpoint
        transport = self._lan.get(device_id)
        if transport is None or not transport.connected:
            transport = FcLanTransport(host, port, self.lan_config)
            try:
                await transport.connect()
                await transport.pair()
            except FcLocalError:
                self.lan_hosts.pop(device_id, None)
                return None
            self._lan[device_id] = transport
        return transport

    async def _ble_transport(self, device_id: str) -> FcBleTransport | None:
        if self.ble_manager is None:
            return None
        address = getattr(self, "_ble_addresses", {}).get(device_id)
        if not address:
            return None
        try:
            return await self.ble_manager.transport(address)
        except FcLocalError:
            return None
        except Exception as err:  # noqa: BLE001 - proxies can raise
            _LOGGER.debug("BLE transport error for %s: %s", device_id, err)
            return None

    async def unlock(self, device_id: str, reason: str = "app") -> ControlResult:
        transport = await self._lan_transport(device_id)
        if transport is not None:
            try:
                await transport.unlock()
                return ControlResult(success=True, message="unlocked via LAN")
            except FcLocalError as err:
                _LOGGER.debug("LAN unlock failed, falling back: %s", err)
        ble = await self._ble_transport(device_id)
        if ble is not None:
            try:
                # the handshake identity (lockId) is deviceBindUserId —
                # the manager registers it per MAC; if the transport's
                # bound lock_id is the deviceuuid (stale registration),
                # rebind via the manager's lock_ids table
                mac = getattr(self, "_ble_addresses", {}).get(device_id)
                if mac and self.ble_manager is not None:
                    registered = (
                        self.ble_manager.lock_ids.get(mac.upper())
                        or self.ble_manager.lock_ids.get(mac)
                    )
                    if registered:
                        ble.lock_id = registered
                await ble.handshake()
                ok = await ble.remote_unlock()
                if ok:
                    return ControlResult(success=True, message="unlocked via BLE")
                _LOGGER.debug("BLE unlock returned failure, falling back to cloud")
            except FcLocalError as err:
                _LOGGER.debug("BLE unlock failed, falling back to cloud: %s", err)
        return await self.client.unlock(device_id, reason=reason)

    async def lock(self, device_id: str) -> ControlResult:
        transport = await self._lan_transport(device_id)
        if transport is not None:
            try:
                await transport.lock()
                return ControlResult(success=True, message="locked via LAN")
            except FcLocalError as err:
                _LOGGER.debug("LAN lock failed, falling back: %s", err)
        ble = await self._ble_transport(device_id)
        if ble is not None:
            try:
                await ble.lock()
                return ControlResult(success=True, message="locked via BLE")
            except FcLocalError as err:
                _LOGGER.debug("BLE lock failed, falling back to cloud: %s", err)
        return await self.client.lock(device_id)

    async def latch(self, device_id: str) -> ControlResult:
        transport = await self._lan_transport(device_id)
        if transport is not None:
            try:
                await transport.latch()
                return ControlResult(success=True, message="latch opened via LAN")
            except FcLocalError as err:
                _LOGGER.debug("LAN latch failed, falling back: %s", err)
        ble = await self._ble_transport(device_id)
        if ble is not None:
            try:
                await ble.latch()
                return ControlResult(success=True, message="latch opened via BLE")
            except FcLocalError as err:
                _LOGGER.debug("BLE latch failed, falling back to cloud: %s", err)
        return await self.client.latch(device_id)

    async def beep(self, device_id: str) -> ControlResult:
        transport = await self._lan_transport(device_id)
        if transport is not None:
            try:
                await transport.beep()
                return ControlResult(success=True, message="beep via LAN")
            except FcLocalError as err:
                _LOGGER.debug("LAN beep failed, falling back: %s", err)
        ble = await self._ble_transport(device_id)
        if ble is not None:
            try:
                await ble.beep()
                return ControlResult(success=True, message="beep via BLE")
            except FcLocalError as err:
                _LOGGER.debug("BLE beep failed, falling back to cloud: %s", err)
        return await self.client.beep(device_id)

    async def status(self, device_id: str) -> LockStatus:
        """Status prefers cloud (rich), local channels as fallback."""
        try:
            return await self.client.get_device_status(device_id)
        except Exception as err:  # noqa: BLE001
            _LOGGER.debug("cloud status failed, trying local: %s", err)
        transport = await self._lan_transport(device_id)
        if transport is not None:
            raw = await transport.read_status_raw()
            if raw:
                from ..api.const import DEVICE_STATUS_MASKS
                from ..api.models import LockStatus as _LS

                st = _LS.from_dev_status(device_id, raw[0], DEVICE_STATUS_MASKS)
                if len(raw) > 1:
                    st.battery = raw[1]
                return st
        ble = await self._ble_transport(device_id)
        if ble is not None:
            return await ble.read_status()
        raise FcLocalError(f"No transport available for {device_id}")
