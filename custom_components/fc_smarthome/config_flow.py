"""Config flow for FC SmartHome, including reauth."""

from __future__ import annotations

import logging

import voluptuous as vol

from homeassistant.config_entries import ConfigEntry, ConfigFlow, OptionsFlow
from homeassistant.core import callback

from .api.client import FcClient
from .api.endpoints import EndpointRegistry
from .api.errors import FcAuthError, FcError
from .const import (
    CONF_COUNTRY_CODE,
    CONF_EMAIL,
    CONF_ENDPOINTS_FILE,
    CONF_FAMILY_ID,
    CONF_LOCAL_BLE,
    CONF_LOCAL_LAN,
    CONF_PASSWORD,
    CONF_POLL_INTERVAL,
    CONF_REGION,
    CONF_TOKEN,
    DEFAULT_POLL_INTERVAL,
    DOMAIN,
)

_LOGGER = logging.getLogger(__name__)


def _protocol_secrets(hass=None) -> dict:
    """Load secureData + RSA private key for the cloud login protocol."""
    from . import _load_protocol_secret

    class _EntryStub:
        data = {}

    return {
        "secure_data": _load_protocol_secret(hass, _EntryStub(), "secure_data"),
        "private_key_b64": _load_protocol_secret(hass, _EntryStub(), "private_key"),
    }


STEP_USER_SCHEMA = vol.Schema(
    {
        vol.Required(CONF_EMAIL): str,
        vol.Optional(CONF_COUNTRY_CODE, default="34"): str,
        vol.Optional(CONF_PASSWORD, default=""): str,
        vol.Optional(CONF_TOKEN, default=""): str,
        vol.Optional(CONF_FAMILY_ID, default=""): str,
        vol.Optional(
            CONF_REGION,
            default="us",
            description="Server channel (extracted from the official app)",
        ): vol.In(["us", "eu", "cn", "ru", "intl-aws", "test", "test2"]),
        vol.Optional(CONF_ENDPOINTS_FILE, default=""): str,
    }
)
REAUTH_SCHEMA = vol.Schema(
    {
        vol.Required(CONF_PASSWORD): str,
    }
)


class FCSmartHomeConfigFlow(ConfigFlow, domain=DOMAIN):
    VERSION = 1

    @staticmethod
    @callback
    def async_get_options_flow(config_entry: ConfigEntry) -> OptionsFlow:
        return FCSmartHomeOptionsFlow(config_entry)

    async def _validate(
        self, email: str, password: str, region: str, endpoints_file: str,
        country_code: str = "34",
    ) -> dict:
        import asyncio

        registry = EndpointRegistry.load(region, endpoints_file or None)
        secrets = await asyncio.to_thread(_protocol_secrets, self.hass)
        if not secrets.get("secure_data") or not secrets.get("private_key_b64"):
            return {"errors": {"base": "missing_protocol_secrets"}}
        client = FcClient(
            email, password, region, registry,
            country_code=country_code, **secrets,
        )
        try:
            await client.login()
        except FcAuthError:
            return {"errors": {"base": "invalid_auth"}}
        except FcError:
            return {"errors": {"base": "cannot_connect"}}
        finally:
            await client.close()
        return {"ok": True}

    async def async_step_user(self, user_input=None):
        errors: dict[str, str] = {}
        if user_input is not None:
            email = user_input[CONF_EMAIL].strip()
            token = user_input.get(CONF_TOKEN, "").strip()
            family_id = user_input.get(CONF_FAMILY_ID, "").strip()
            password = user_input.get(CONF_PASSWORD, "").strip()
            region = user_input.get(CONF_REGION, "us")
            endpoints_file = user_input.get(CONF_ENDPOINTS_FILE, "")
            country_code = (user_input.get(CONF_COUNTRY_CODE) or "34").strip()

            if token:
                # Direct Token / App Session setup (for sessions extracted
                # from the official app). The token alone is not enough for
                # the encrypted protocol — we need the negotiated session
                # key, so perform a full login when password + protocol
                # secrets are available; otherwise store the token as-is
                # (device discovery will fail gracefully until reauth).
                from .api.models import TokenPair

                entry_data = dict(user_input)
                entry_data["tokens"] = {
                    "access_token": token,
                    "family_id": family_id or None,
                }
                import asyncio as _asyncio
                registry = EndpointRegistry.load(region, endpoints_file or None)
                secrets = await _asyncio.to_thread(_protocol_secrets, self.hass)
                client = FcClient(
                    email, password, region, registry,
                    country_code=country_code, **secrets,
                )
                client.tokens = TokenPair(access_token=token, family_id=family_id or None)
                try:
                    if password and secrets.get("secure_data"):
                        # full login: negotiates the session key and
                        # replaces the token with a fresh one
                        await client.login()
                        if client.tokens:
                            entry_data["tokens"] = client.tokens.to_dict()
                    cloud_devices = await client.get_devices()
                    if cloud_devices:
                        entry_data["devices"] = [
                            {
                                "device_id": d.device_id,
                                "name": d.name,
                                "model": d.model,
                                "category": d.category,
                                "manufacturer": d.manufacturer,
                                "online": d.online,
                                "capabilities": d.capabilities,
                            }
                            for d in cloud_devices
                        ]
                except Exception as err:
                    _LOGGER.debug("Could not auto-fetch devices from cloud: %s", err)
                finally:
                    await client.close()

                await self.async_set_unique_id(email.lower())
                self._abort_if_unique_id_configured()
                return self.async_create_entry(
                    title=f"FC SmartHome ({email})",
                    data=entry_data,
                    options={
                        CONF_LOCAL_BLE: True,
                        CONF_LOCAL_LAN: True,
                        CONF_POLL_INTERVAL: 30,
                    },
                )
            elif password:
                result = await self._validate(
                    email,
                    password,
                    region,
                    endpoints_file,
                    country_code,
                )
                if result.get("ok"):
                    await self.async_set_unique_id(email.lower())
                    self._abort_if_unique_id_configured()
                    return self.async_create_entry(
                        title=email,
                        data=user_input,
                        options={
                            CONF_LOCAL_BLE: True,
                            CONF_LOCAL_LAN: True,
                            CONF_POLL_INTERVAL: 30,
                        },
                    )
                errors = result.get("errors", {})
            else:
                errors = {"base": "invalid_auth"}
        return self.async_show_form(
            step_id="user",
            data_schema=STEP_USER_SCHEMA,
            errors=errors,
        )


    async def async_step_reauth(self, entry_data):
        return await self.async_step_reauth_confirm()

    async def async_step_reauth_confirm(self, user_input=None):
        errors: dict[str, str] = {}
        if user_input is not None:
            entry = self._get_reauth_entry()
            data = dict(entry.data)
            data[CONF_PASSWORD] = user_input[CONF_PASSWORD]
            result = await self._validate(
                data[CONF_EMAIL],
                data[CONF_PASSWORD],
                data.get(CONF_REGION, "us"),
                data.get(CONF_ENDPOINTS_FILE, ""),
                data.get(CONF_COUNTRY_CODE, "34"),
            )
            if result.get("ok"):
                return self.async_update_reload_and_abort(
                    entry, data=data, reason="reauth_successful"
                )
            errors = result.get("errors", {})
        return self.async_show_form(
            step_id="reauth_confirm",
            data_schema=REAUTH_SCHEMA,
            errors=errors,
        )


class FCSmartHomeOptionsFlow(OptionsFlow):
    def __init__(self, entry: ConfigEntry) -> None:
        self.entry = entry

    async def async_step_init(self, user_input=None):
        if user_input is not None:
            return self.async_create_entry(title="", data=user_input)
        current = self.entry.options
        return self.async_show_form(
            step_id="init",
            data_schema=vol.Schema(
                {
                    vol.Optional(
                        CONF_POLL_INTERVAL,
                        default=current.get(CONF_POLL_INTERVAL, DEFAULT_POLL_INTERVAL),
                    ): vol.All(vol.Coerce(int), vol.Range(min=15, max=3600)),
                    vol.Optional(
                        CONF_LOCAL_LAN,
                        default=current.get(CONF_LOCAL_LAN, True),
                    ): bool,
                    vol.Optional(
                        CONF_LOCAL_BLE,
                        default=current.get(CONF_LOCAL_BLE, False),
                    ): bool,
                }
            ),
        )
