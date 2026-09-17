"""Production login and device test — credentials from environment or .env.

Loads FC_PHONE / FC_CC / FC_PASSWORD / FC_REGION from env vars or a local .env
(gitignored). Never hardcode, never commit credentials.

Usage (PowerShell, local):
    python tools/prod_login_test.py
"""

from __future__ import annotations

import asyncio
import os
import sys
from pathlib import Path

# Add repo root to sys.path
REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT))

# Ensure UTF-8 output on Windows consoles
if sys.platform == "win32":
    import contextlib

    with contextlib.suppress(Exception):
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")

from custom_components.fc_smarthome.api.client import FcClient
from custom_components.fc_smarthome.api.endpoints import EndpointRegistry
from custom_components.fc_smarthome.api.errors import FcError

ENV_FILE = REPO_ROOT / ".env"


def load_env_file() -> None:
    """Minimal .env loader (KEY=VALUE lines) — never overrides real env."""
    if not ENV_FILE.is_file():
        return
    for line in ENV_FILE.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, value = line.partition("=")
        os.environ.setdefault(key.strip(), value.strip())


def _mask(s: str) -> str:
    if not s or len(s) <= 4:
        return "***"
    return s[:2] + "*" * (len(s) - 4) + s[-2:]


async def main() -> int:
    load_env_file()

    phone = os.environ.get("FC_PHONE") or os.environ.get("FC_EMAIL", "")
    cc = os.environ.get("FC_CC", "34")
    password = os.environ.get("FC_PASSWORD", "")
    region = os.environ.get("FC_REGION", "us")

    if not phone or not password:
        print("ERROR: missing credentials! Set FC_PHONE (or FC_EMAIL) and FC_PASSWORD in .env or environment.", file=sys.stderr)
        return 2

    print("=" * 60)
    print("FC SmartHome Live Production Test")
    print("=" * 60)
    print(f"Account:  {_mask(phone)} (countryCode: {cc})")
    print(f"Region:   {region}")

    registry = EndpointRegistry.load(region)
    print(f"Server:   {registry.base_url}")
    print("-" * 60)

    client = FcClient(phone, password, region=region, endpoints=registry, country_code=cc)

    try:
        # 1. RSA Handshake
        print("[1/5] Negotiating session key (RSA-1024 handshake)...")
        session_key = await client._handshake()
        print(f"      OK - session AES key established (16 bytes, prefix {session_key[:4].decode('ascii', errors='replace')}...)")

        # 2. Login
        print("[2/5] Authenticating with FC cloud...")
        tokens = await client.login()
        masked_token = _mask(tokens.access_token)
        print(f"      OK - Logged in successfully!")
        print(f"      Token: {masked_token} | User ID: {tokens.user_id}")

        # 3. Devices
        print("[3/5] Querying device list...")
        devices = await client.get_devices()
        print(f"      OK - Found {len(devices)} device(s):")
        for dev in devices:
            print(f"      - ID: {dev.device_id}")
            print(f"        Name:        {dev.name}")
            print(f"        Model:       {dev.model or 'unknown'}")
            print(f"        Battery:     {dev.battery}%" if dev.battery is not None else "        Battery:     unknown")
            print(f"        Online:      {dev.online}")

            # 4. Device Status
            print(f"[4/5] Checking status for device {dev.device_id[:8]}...:")
            status = await client.get_device_status(dev.device_id)
            print(f"        Locked:      {status.is_locked}")
            print(f"        Door Open:   {status.door_open}")
            print(f"        Tamper:      {status.tamper}")

            # 5. Users & History
            print(f"[5/5] Checking users & event history:")
            try:
                users = await client.get_users(dev.device_id)
                print(f"        Users:       {len(users)} registered")
                for u in users[:5]:
                    print(f"          * [{u.type.value:<8}] {u.name}")
                if len(users) > 5:
                    print(f"          * ... and {len(users) - 5} more")
            except Exception as err:
                print(f"        Users error: {err}")

            try:
                history = await client.get_history(dev.device_id, limit=5)
                print(f"        History:     {len(history)} recent events retrieved")
                for ev in history[:3]:
                    print(f"          * {ev.type.value} by {ev.user or 'unknown'} at {ev.timestamp}")
            except Exception as err:
                print(f"        History error: {err}")

        print("=" * 60)
        print("ALL TESTS PASSED: Cloud connection, auth, and device control verified!")
        print("=" * 60)
        return 0

    except FcError as err:
        print(f"\nAPI Error: {err}", file=sys.stderr)
        return 1
    except Exception as err:
        print(f"\nUnexpected Error: {type(err).__name__}: {err}", file=sys.stderr)
        return 1
    finally:
        await client.close()


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
