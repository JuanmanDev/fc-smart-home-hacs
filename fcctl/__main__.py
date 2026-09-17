"""fcctl - the single CLI for FC SmartHome.

A thin layer over custom_components.fc_smarthome.api so CLI and HA share
the exact same protocol implementation. No duplicated logic.
"""

from __future__ import annotations

import argparse
import asyncio
import contextlib
import getpass
import json
import logging
import os
import sys
from pathlib import Path

# Fix Windows console UTF-8 output (for emojis in device/user names)
if sys.platform == "win32":
    with contextlib.suppress(Exception):
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")

# Allow running from repo root without installation
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from custom_components.fc_smarthome.api.client import FcClient  # noqa: E402
from custom_components.fc_smarthome.api.const import USER_TYPE_INT_MAP  # noqa: E402
from custom_components.fc_smarthome.api.endpoints import EndpointRegistry  # noqa: E402
from custom_components.fc_smarthome.api.errors import FcError  # noqa: E402
from custom_components.fc_smarthome.api.models import LockUserType  # noqa: E402

TOKEN_FILE = Path.home() / ".fcsmarthome" / "tokens.json"


def _load_env_file() -> None:
    """Load .env file from cwd or repo root if present without overriding existing env."""
    for candidate in [Path.cwd() / ".env", Path(__file__).resolve().parents[1] / ".env"]:
        if candidate.is_file():
            try:
                for line in candidate.read_text(encoding="utf-8").splitlines():
                    line = line.strip()
                    if not line or line.startswith("#") or "=" not in line:
                        continue
                    k, _, v = line.partition("=")
                    os.environ.setdefault(k.strip(), v.strip())
                break
            except Exception:
                pass


def out_json(data) -> None:
    def _default(obj):
        if hasattr(obj, "to_dict"):
            return obj.to_dict()
        if hasattr(obj, "value"):
            return obj.value
        if hasattr(obj, "isoformat"):
            return obj.isoformat()
        return str(obj)

    print(json.dumps(data, indent=2, default=_default, ensure_ascii=False))


def build_client(args) -> FcClient:
    _load_env_file()
    account = (
        getattr(args, "phone", None)
        or getattr(args, "email", None)
        or os.environ.get("FC_PHONE")
        or os.environ.get("FC_EMAIL")
    )
    password = getattr(args, "password", None) or os.environ.get("FC_PASSWORD")
    if (getattr(args, "email", None) or getattr(args, "phone", None)) and not password:
        password = getpass.getpass("Password: ")
    region = getattr(args, "region", None) or os.environ.get("FC_REGION", "us")
    country_code = os.environ.get("FC_CC", "34")
    registry = EndpointRegistry.load(region, getattr(args, "endpoints_file", None))
    if not account or not password:
        # try stored tokens only if explicitly allowed
        if not (TOKEN_FILE.exists() and getattr(args, "use_stored", False)):
            print("error: provide --phone/--email/--password or set FC_PHONE/FC_EMAIL/FC_PASSWORD in .env", file=sys.stderr)
            sys.exit(2)
    client = FcClient(
        account or "",
        password or "",
        region,
        registry,
        country_code=country_code,
    )
    if TOKEN_FILE.exists() and getattr(args, "use_stored", False):
        try:
            data = json.loads(TOKEN_FILE.read_text())
            from custom_components.fc_smarthome.api.models import TokenPair

            client.set_tokens(TokenPair.from_dict(data))
        except Exception:
            pass
    return client


async def _login_flow(client: FcClient, interactive: bool) -> None:
    if client.tokens and client.tokens.valid:
        return
    if not client.email or not client._password:
        if not interactive:
            raise FcError("no credentials")
        client.email = input("Email: ")
        client._password = getpass.getpass("Password: ")
    await client.login()
    if client.tokens:
        TOKEN_FILE.parent.mkdir(parents=True, exist_ok=True)
        TOKEN_FILE.write_text(json.dumps(client.tokens.to_dict()))
        try:
            os.chmod(TOKEN_FILE, 0o600)
        except OSError:
            pass


# ---------- commands ----------


async def cmd_login(args) -> None:
    client = build_client(args)
    await _login_flow(client, interactive=True)
    print(f"Logged in as {client.email}. Tokens stored in {TOKEN_FILE}")
    await client.close()


async def cmd_logout(args) -> None:
    if TOKEN_FILE.exists():
        TOKEN_FILE.unlink()
    registry = EndpointRegistry.load(getattr(args, "region", "us"))
    client = FcClient("", "", getattr(args, "region", "us"), registry)
    if TOKEN_FILE.exists():
        TOKEN_FILE.unlink()
    if os.environ.get("FC_EMAIL") and os.environ.get("FC_PASSWORD"):
        client = build_client(args)
        try:
            await _login_flow(client, interactive=False)
            await client.logout()
        except FcError:
            pass
        await client.close()
    print("Logged out (stored tokens removed).")


async def cmd_devices(args) -> None:
    client = build_client(args)
    await _login_flow(client, interactive=False)
    devices = await client.get_devices()
    if args.json:
        out_json([d.raw for d in devices])
    else:
        for d in devices:
            battery = f" battery={d.battery}%" if d.battery is not None else ""
            state = "online" if d.online else "offline"
            print(f"{d.device_id}  {d.name!r} [{d.category or '?'}] {state}{battery}")
    await client.close()


async def cmd_status(args) -> None:
    client = build_client(args)
    await _login_flow(client, interactive=False)
    status = await client.get_device_status(args.device_id)
    out_json(status)
    await client.close()


async def cmd_history(args) -> None:
    client = build_client(args)
    await _login_flow(client, interactive=False)
    events = await client.get_history(args.device_id, limit=args.limit)
    if args.json:
        out_json([ev.to_dict() for ev in events])
    else:
        for ev in events:
            when = ev.timestamp.isoformat() if ev.timestamp else "?"
            who = ev.user or "-"
            method = ev.method.value if ev.method else "-"
            print(f"{when}  {ev.type.value:<14} {method:<10} {who}")
    await client.close()


async def cmd_users(args) -> None:
    client = build_client(args)
    await _login_flow(client, interactive=False)
    users = await client.get_users(args.device_id)
    if args.json:
        out_json([u.__dict__ for u in users])
    else:
        for u in users:
            active = "" if u.active else " [disabled]"
            print(f"{u.user_id:<6} {u.type.value:<10} {u.name}{active}")
    await client.close()


async def cmd_add_user(args) -> None:
    client = build_client(args)
    await _login_flow(client, interactive=False)
    result = await client.add_user(
        args.device_id,
        args.name,
        LockUserType.coerce(args.user_type),
        password=args.password_value,
        card_id=args.card_id,
    )
    out_json(result)
    await client.close()


async def cmd_del_user(args) -> None:
    client = build_client(args)
    await _login_flow(client, interactive=False)
    result = await client.delete_user(args.device_id, args.user_id)
    out_json(result)
    await client.close()


async def cmd_rename_user(args) -> None:
    client = build_client(args)
    await _login_flow(client, interactive=False)
    result = await client.rename_user(args.device_id, args.user_id, args.name)
    out_json(result)
    await client.close()


async def cmd_enroll_fp(args) -> None:
    client = build_client(args)
    await _login_flow(client, interactive=False)
    result = await client.enroll_fingerprint(args.device_id, args.name)
    print("Touch the fingerprint sensor on the lock until enrollment completes.")
    out_json(result)
    await client.close()


async def cmd_unlock(args) -> None:
    client = build_client(args)
    await _login_flow(client, interactive=False)
    result = await client.unlock(args.device_id, reason="cli")
    out_json(result)
    await client.close()


async def cmd_lock(args) -> None:
    client = build_client(args)
    await _login_flow(client, interactive=False)
    result = await client.lock(args.device_id)
    out_json(result)
    await client.close()


async def cmd_latch(args) -> None:
    client = build_client(args)
    await _login_flow(client, interactive=False)
    result = await client.latch(args.device_id)
    out_json(result)
    await client.close()


async def cmd_bell(args) -> None:
    client = build_client(args)
    await _login_flow(client, interactive=False)
    result = await client.ring_bell(args.device_id)
    out_json(result)
    await client.close()


async def cmd_beep(args) -> None:
    client = build_client(args)
    await _login_flow(client, interactive=False)
    result = await client.beep(args.device_id)
    out_json(result)
    await client.close()


async def cmd_child_lock(args) -> None:
    client = build_client(args)
    await _login_flow(client, interactive=False)
    result = await client.set_child_lock(args.device_id, args.enabled)
    out_json(result)
    await client.close()


async def cmd_watch(args) -> None:
    client = build_client(args)
    await _login_flow(client, interactive=False)
    print("Watching for new lock events (Ctrl+C to stop)...")
    seen: set = set()
    try:
        while True:
            devices = await client.get_devices()
            for d in devices:
                events = await client.get_history(d.device_id, limit=10)
                for ev in events:
                    key = (ev.timestamp, ev.type.value, ev.user_id, ev.user)
                    if key in seen:
                        continue
                    seen.add(key)
                    when = ev.timestamp.isoformat() if ev.timestamp else "?"
                    print(f"[{when}] {d.name}: {ev.type.value} via {ev.method.value if ev.method else '?'} by {ev.user or 'someone'}")
            await asyncio.sleep(args.interval)
    except KeyboardInterrupt:
        pass
    finally:
        await client.close()


async def cmd_ble_scan(args) -> None:
    from custom_components.fc_smarthome.local.ble import FcBleManager, BleConfig

    registry = EndpointRegistry.load(getattr(args, "region", "us"))
    manager = FcBleManager(BleConfig.from_registry(registry.ble))
    found = await manager.scan(timeout=args.timeout)
    out_json(found)


async def cmd_ble_unlock(args) -> None:
    from custom_components.fc_smarthome.local.ble import FcBleManager, BleConfig

    registry = EndpointRegistry.load(getattr(args, "region", "us"))
    manager = FcBleManager(BleConfig.from_registry(registry.ble, pair_code=args.pair_code))
    transport = await manager.transport(args.address)
    await transport.unlock()
    print("Unlock command sent over BLE.")
    await manager.close()


async def cmd_ble_status(args) -> None:
    from custom_components.fc_smarthome.local.ble import FcBleManager, BleConfig

    registry = EndpointRegistry.load(getattr(args, "region", "us"))
    manager = FcBleManager(BleConfig.from_registry(registry.ble, pair_code=args.pair_code))
    transport = await manager.transport(args.address)
    status = await transport.read_status()
    out_json(status)
    await manager.close()


async def cmd_lan_discover(args) -> None:
    """Discover FC/Alink devices on the local network (mDNS + UDP)."""
    from custom_components.fc_smarthome.local.lan import discover_lan_devices, probe_coap

    found = await discover_lan_devices(timeout=args.timeout)
    out_json(found)
    for d in found:
        if d["source"] == "udp-broadcast":
            result = await probe_coap(d["ip"])
            if result:
                print(f"Alink CoAP confirmed at {result['ip']} code={result['coap_code']}")


async def cmd_lan_unlock(args) -> None:
    """Unlock a lock over the LAN (WiFi lock / gateway TCP channel)."""
    from custom_components.fc_smarthome.local.lan import FcLanTransport, LanConfig
    from custom_components.fc_smarthome.api.endpoints import EndpointRegistry

    registry = EndpointRegistry.load(getattr(args, "region", "us"))
    config = LanConfig.from_registry(registry.lan, pair_code=args.pair_code)
    transport = FcLanTransport(args.host, args.port, config)
    await transport.connect()
    await transport.pair()
    await transport.unlock()
    print(f"Unlock command sent over LAN to {args.host}:{args.port}.")
    await transport.disconnect()


async def cmd_lan_scan_ports(args) -> None:
    """Find the TCP command port on a gateway/lock host."""
    from custom_components.fc_smarthome.local.lan import find_open_command_port

    port = await find_open_command_port(args.host)
    print(f"{args.host}: command port = {port}" if port else f"{args.host}: no known port open")


async def cmd_lan_register(args) -> None:
    """Register a LAN device with its Alink productKey/deviceName and verify it."""
    from custom_components.fc_smarthome.local.lan import confirm_fc_device

    info = await confirm_fc_device(args.host, args.product_key, args.device_name)
    if info:
        print(f"VERIFIED {args.host} as pk={args.product_key} dn={args.device_name}")
        out_json(info)
    else:
        print(f"NOT verified: {args.host} did not answer an Alink RPC with pk/dn. "
              "Check pk/dn (from the cloud device list or a capture).")


async def cmd_alink_call(args) -> None:
    """Raw Alink RPC to a LAN device (for protocol exploration)."""
    from custom_components.fc_smarthome.local.alink import AlinkLanDevice

    dev = AlinkLanDevice(
        args.host,
        product_key=args.product_key,
        device_name=args.device_name,
    )
    result = await dev._rpc(args.method, json.loads(args.params) if args.params else {})
    out_json(result)


async def cmd_probe_endpoints(args) -> None:
    sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "tools"))
    from probe_endpoints import probe_all  # noqa: E402

    results = await probe_all(EndpointRegistry.load(args.region, args.endpoints_file))
    out_json(results)


async def cmd_discover(args) -> None:
    """Self-configuration: discover cloud endpoints + BLE locks, no JSON needed."""
    from custom_components.fc_smarthome.api.discovery import (
        discover_login_endpoint,
        resolve_candidate_ips,
    )

    print("Resolving candidate hosts...")
    ips = resolve_candidate_ips()
    for host, ip in ips.items():
        print(f"  {host} -> {ip or 'NXDOMAIN'}")
    print("\nProbing for the FC login endpoint (vendor envelope + crypto)...")
    discovery = await discover_login_endpoint()
    if discovery and discovery.get("host"):
        print(f"\nFOUND: {discovery['host']}{discovery['login_path']}")
        print(f"  status={discovery['status']} body={discovery.get('body', '')[:120]}")
        # persist so future runs use it automatically
        from custom_components.fc_smarthome.api.discovery import save_cached

        save_cached(discovery)
        print("  saved to ~/.fcsmarthome/discovered.json (auto-used by fcctl/HA)")
    else:
        probes = (discovery or {}).get("probes", [])
        print(f"\nNo confirmed endpoint yet ({len(probes)} probes).")
        print("Next: capture the app traffic (tools/HARVEST.md) to pin the host.")

    if args.ble:
        print("\nScanning Bluetooth for locks (self-configuring)...")
        try:
            from custom_components.fc_smarthome.local.ble import FcBleManager, BleConfig

            registry = EndpointRegistry.load(args.region)
            manager = FcBleManager(BleConfig.from_registry(registry.ble))
            found = await manager.scan(timeout=args.ble_timeout, broad=True)
            for d in found:
                mark = " [likely lock]" if d.get("possibly_lock") else ""
                print(f"  {d['address']}  {d['name']}{mark} rssi={d.get('rssi')}")
            if not found:
                print("  no BLE devices found")
        except Exception as err:  # noqa: BLE001
            print(f"  BLE scan unavailable: {err}")


def build_parser() -> argparse.ArgumentParser:
    _load_env_file()
    parser = argparse.ArgumentParser(
        prog="fcctl",
        description="FC SmartHome (Fingerchip) control CLI",
    )
    parser.add_argument("--phone", help="account phone (or FC_PHONE)")
    parser.add_argument("--email", help="account email (or FC_EMAIL)")
    parser.add_argument("--password", help="account password (or FC_PASSWORD)")
    parser.add_argument(
        "--region",
        default=os.environ.get("FC_REGION", "us"),
        choices=["us", "eu", "cn", "ru", "intl-aws", "test", "test2"],
        help="server channel (from the official app: us/eu/cn/ru -> www.fcsmartlock.com, intl-aws -> 18.219.242.80, test/test2)",
    )
    parser.add_argument("--endpoints-file", help="endpoints override JSON path")
    parser.add_argument("--use-stored", action="store_true", help="reuse tokens from ~/.fcsmarthome/tokens.json")
    parser.add_argument("--debug", action="store_true", help="verbose logging")
    parser.set_defaults(func=None)

    sub = parser.add_subparsers(dest="command", required=True)

    p = sub.add_parser("login", help="authenticate and store tokens")
    p.set_defaults(func=cmd_login)

    p = sub.add_parser("logout", help="invalidate stored tokens")
    p.set_defaults(func=cmd_logout)

    p = sub.add_parser("devices", help="list devices")
    p.add_argument("--json", action="store_true", dest="json", help="raw JSON output")
    p.set_defaults(func=cmd_devices)

    def add_device(p):
        p.add_argument("device_id")

    p = sub.add_parser("status", help="device status")
    add_device(p)
    p.set_defaults(func=cmd_status)

    p = sub.add_parser("history", help="access history")
    add_device(p)
    p.add_argument("--limit", type=int, default=50)
    p.add_argument("--json", action="store_true", dest="json")
    p.set_defaults(func=cmd_history)

    p = sub.add_parser("users", help="list lock users")
    add_device(p)
    p.add_argument("--json", action="store_true", dest="json")
    p.set_defaults(func=cmd_users)

    p = sub.add_parser("add-user", help="add password/card/NFC user")
    add_device(p)
    p.add_argument("--name", required=True)
    p.add_argument("--user-type", required=True, choices=[v for v in USER_TYPE_INT_MAP.values()])
    p.add_argument("--password-value", dest="password_value")
    p.add_argument("--card-id", dest="card_id")
    p.set_defaults(func=cmd_add_user)

    p = sub.add_parser("del-user", help="remove a user")
    add_device(p)
    p.add_argument("user_id")
    p.set_defaults(func=cmd_del_user)

    p = sub.add_parser("rename-user", help="rename a user")
    add_device(p)
    p.add_argument("user_id")
    p.add_argument("--name", required=True)
    p.set_defaults(func=cmd_rename_user)

    p = sub.add_parser("enroll-fingerprint", help="start fingerprint enrollment")
    add_device(p)
    p.add_argument("--name", required=True)
    p.set_defaults(func=cmd_enroll_fp)

    p = sub.add_parser("unlock", help="unlock (cloud)")
    add_device(p)
    p.set_defaults(func=cmd_unlock)

    p = sub.add_parser("lock", help="lock (cloud)")
    add_device(p)
    p.set_defaults(func=cmd_lock)

    p = sub.add_parser("latch", help="open latch (cloud)")
    add_device(p)
    p.set_defaults(func=cmd_latch)

    p = sub.add_parser("bell", help="ring doorbell (cloud)")
    add_device(p)
    p.set_defaults(func=cmd_bell)

    p = sub.add_parser("beep", help="locate via beep (cloud)")
    add_device(p)
    p.set_defaults(func=cmd_beep)

    p = sub.add_parser("child-lock", help="enable/disable child lock")
    add_device(p)
    p.add_argument("enabled", type=lambda s: s.lower() in ("1", "true", "yes", "on"))
    p.set_defaults(func=cmd_child_lock)

    p = sub.add_parser("watch", help="poll history and print new events")
    p.add_argument("--interval", type=float, default=10.0)
    p.set_defaults(func=cmd_watch)

    p = sub.add_parser("ble-scan", help="scan for locks over Bluetooth")
    p.add_argument("--timeout", type=float, default=10.0)
    p.set_defaults(func=cmd_ble_scan)

    p = sub.add_parser("ble-unlock", help="unlock locally over BLE")
    p.add_argument("address")
    p.add_argument("--pair-code")
    p.set_defaults(func=cmd_ble_unlock)

    p = sub.add_parser("ble-status", help="read status locally over BLE")
    p.add_argument("address")
    p.add_argument("--pair-code")
    p.set_defaults(func=cmd_ble_status)

    p = sub.add_parser("lan-discover", help="discover FC/Alink devices on the LAN")
    p.add_argument("--timeout", type=float, default=5.0)
    p.set_defaults(func=cmd_lan_discover)

    p = sub.add_parser("lan-unlock", help="unlock a lock over local LAN/TCP")
    p.add_argument("host")
    p.add_argument("--port", type=int, default=8060)
    p.add_argument("--pair-code")
    p.set_defaults(func=cmd_lan_unlock)

    p = sub.add_parser("lan-ports", help="find the TCP command port on a host")
    p.add_argument("host")
    p.set_defaults(func=cmd_lan_scan_ports)

    p = sub.add_parser(
        "lan-register",
        help="verify a LAN device with its Alink productKey/deviceName",
    )
    p.add_argument("host")
    p.add_argument("--product-key", required=True)
    p.add_argument("--device-name", required=True)
    p.set_defaults(func=cmd_lan_register)

    p = sub.add_parser(
        "alink-call",
        help="raw Alink RPC to a LAN device (protocol exploration)",
    )
    p.add_argument("host")
    p.add_argument("--product-key", required=True)
    p.add_argument("--device-name", required=True)
    p.add_argument("--method", required=True, help="e.g. thing.deviceInfo.get")
    p.add_argument("--params", default="{}")
    p.set_defaults(func=cmd_alink_call)

    p = sub.add_parser("probe", help="probe cloud endpoint candidates")
    p.add_argument("--endpoints-file")
    p.set_defaults(func=cmd_probe_endpoints)

    p = sub.add_parser(
        "discover",
        help="self-configure: find cloud endpoints (+ BLE locks) with no JSON",
    )
    p.add_argument("--ble", action="store_true", help="also scan Bluetooth")
    p.add_argument("--ble-timeout", type=float, default=10.0)
    p.set_defaults(func=cmd_discover)

    return parser


async def amain() -> int:
    parser = build_parser()
    args = parser.parse_args()
    logging.basicConfig(
        level=logging.DEBUG if args.debug else logging.WARNING,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )
    if args.func is None:
        parser.print_help()
        return 1
    try:
        await args.func(args)
        return 0
    except FcError as err:
        print(f"error: {err}", file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        return 130


def main() -> None:
    sys.exit(asyncio.run(amain()))


if __name__ == "__main__":
    main()
