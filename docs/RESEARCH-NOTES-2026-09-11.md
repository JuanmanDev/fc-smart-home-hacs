# Live Research Notes — 2026-09-11/12 session

## Session update 2026-09-14 — BLE UNLOCK WORKS END TO END ✅

**The door opened via `fc_smarthome.ble_unlock`** (verified 3x live, last run
returned `ok: true` in 57.6s cold / instant once the version is learned).

### Root causes found by re-reading the app's H5 bundle modules

The official protocol sources (extracted to
`%TEMP%\opencode\webctrl\smart_lock\js\Lock_Controller-4.5.11-*.js`):

1. **The L5-WIFI-QINGKE speaks protocol v1 (0xFC frames), NOT v2.**
   - v1 frame: start 0xFC, inner message WITHOUT the xor trailer, length
     counts header(8)+data only (module 45cc getBytes: `a=this.length-1`).
   - v2 frame: start 0xFD, inner WITH xor byte, length 9+data.
   - We sent v2 only -> the lock silently ignored EVERYTHING for days.
   - First v1 handshake attempt (identity=uid 341727051920) got an immediate
     reply `data[0]=1` (rejected identity) — proving the transport was fine.
2. **Handshake identity = `device.deviceBindUserId`** (32-hex
   `2d9cee41d51d4b4d948de24f4fd6bfb6`), NOT deviceuuid. Verified in
   chunk-d8ca607a @46450: EVERY `$plugin.*` call passes
   `m.value.deviceBindUserId` — `openLock(getBleKey(), getBleMac(),
   deviceBindUserId)`. getBleKey = bluetoothKey (or DEFAULT_AES_KEY),
   getBleMac = `uid || mac`.
   - deviceuuid/zeros/uid identities => lock replies result=1 (validate
     failed). deviceBindUserId => **result=0 + session AES key + full device
     info** (model L5, fw Ver:B2.7.3.64, protocol 6.5, MAC).
3. **The golden "heart" prime was HARMFUL.** The app only writes it on an
   already-established session (loss prevention, module 65eb he()); on a
   fresh GATT connect the FIRST frame must be the handshake (index 1).
   Our heart write used index 2 and desynchronized the lock's index.
4. **Seq convention**: next index = response.index + 1 (module 65eb
   `se=e.index+1` after EVERY successful response). Unlock after handshake
   uses that, not a hardcoded 1.

### The working exchange (live capture 2026-09-14 23:03)

```
-> fc0036006aae... (v1 handshake, identity=deviceBindUserId, seq=1)
<- fc00560004ea... (4 GATT notifications: result=0 + sessionkey + devinfo)
-> fc0016000e22... (cat=4 cmd=0x10 open, seq=resp.index+1)
<- fc001600fcde... (open confirmed)   => DOOR OPENS
```

### Code changes (this session, deployed + verified)

- `local/ble.py`: v1/v2 codec (encode/decode/build/parse with correct v1
  length semantics), version auto-detect from lock responses + per-MAC
  learning in the manager (`register_version`, `on_frame_parsed` callback),
  handshake identity priority (bound lock_id = deviceBindUserId), v1-first
  interleave with short timeouts (4s) so a cold start doesn't burn the wake
  window, seq sync from responses, REMOVED the heart prime.
- `api/client.py`: copy `deviceBindUserId` + `uid` into capabilities.
- `__init__.py`: probe tries deviceBindUserId FIRST; probe/unlock retry the
  GATT connect 3x (proxies at -97dBm are flaky); unlock registers
  deviceBindUserId as lock identity.
- `local/router.py` + `coordinator.py`: use deviceBindUserId for the
  handshake everywhere; lock.py setup_entry restored (it was missing —
  the lock entity never even set up!).
- `tools/ble_probe_remote.py`: one-command live probe/unlock with countdown.

### Operational notes

- The unlock flow needs the lock AWAKE (touch keypad / press 4+# for the
  1-min wake window) — same as the official app (WakeLockByPress string).
  After the first successful handshake in an HA process, the learned v1
  version makes subsequent handshakes immediate.
- ESP32 proxies (living-cover C8:F0:9E:4A:24:3A @ -97dBm, kitchen @ -99)
  are marginal: GATT connects fail ~50% — the retry loops handle it.
  A proxy closer to the lock would make it fully reliable.


## Session update 2026-09-12 ~21:15 — BLE CHANNEL BUILD (in progress)

### Awake-window test RESULT (from today's user test)
- User pressed the BELL on the lock -> cloud event `lock.message.lock.bell`
  arrived in ~2s (lock awake & cloud-connected!) -> our openLock fired 5x
  over the following ~50s -> **ALL returned HTTP 682 null**.
- User then unlocked with FINGERPRINT -> 5 more openLock attempts -> 682.
- **THEORY DEAD: the cloud openLock 682 is NOT a sleep issue.** The vendor
  backend simply cannot relay the open for this lock (server-side policy or
  the relay needs a channel we don't have). The official app also fails
  (it shows WakeLockByPress "press 4 and #" and then rejects).
- The keypad light pattern (0-8-5-2 bottom-up) + failure beep the user saw
  is the lock's wake handshake animation, NOT a code entry failure.

### BLE protocol — FULLY REVERSED from the official app bundle
Source: `%TEMP%\opencode\webctrl\smart_lock\js\Lock_Controller-4.5.11-*.js`
(the app's H5 control page served by the vendor, extracted 2026-09-09).
Library: `fcble/` (repo root) — VERIFIED byte-for-byte against a real frame
found inside the bundle:
  `FD FF 16 00 08 8AAF3DC1ABE8D57CCBB83CAE35C2AF 6B FE`
decrypts (key = raw bytes of bluetoothKey) to `09 00 02 00 00 00 F0 30 CB`
= len 9 LE, index 2 LE, cat 0xF0 SPECIAL, cmd 0x30, xor 0xCB.

Wire format (FCBlePackage v2):
- frame: FD pid lenLo lenHi <AES payload> xor FE; xor = pid^lenLo^lenHi^payload
- inner: len LE u16 (=9+datalen) + index LE u32 + cat(1) + cmd(1) + data + xor
- AES-128-ECB, key = RAW 16 BYTES from the 32-hex bluetoothKey string
  (CryptoJS enc.Hex.parse), zero-padded plaintext, NoPadding
- handshake = cat 2 cmd 8 (VERIFY_IDENTITY): data = lockId 32B ASCII
  (the CLOUD deviceuuid!) + [yr-2000,mon,day,h,m,s,tz] (7B) — response:
  [0]=result(0/241 ok), then session aeskey(16)+mac(12)+protoVer(3)+
  model(8)+fw(15)+wakeSource(2)+fpVer(15)
- unlock = cat 4 cmd 16 data=01 (FCBleOpenMessage); also cat 4 cmd 24
  data=userId LE u16 (FCBleOpenWithIdMessage)
- GATT: scan service 0000-01fa; service FFE0; write+notify char FFE1
  (write-without-response ONLY — "Write not permitted" with response=True)
- the app writes frames in <=20-byte chunks (O=20 in the JS bridge)

Tests: `tests/test_fcble_protocol.py` (12 tests, golden-frame verified),
`tools/ble_test_offline.py`. All 59 repo tests pass.

### ESP32 Bluetooth proxies (HA container)
- Two ESP32s act as BT proxies and SEE the lock: living-cover
  (C8:F0:9E:4A:24:3A) rssi -96/-97, kitchen (C8:F0:9E:51:22:B2) -99.
  ESPHome configs: /docker/esphome/config/{kitchen,living-cover}.yaml
- **BUG FIXED: living-cover had `bluetooth_proxy:` WITHOUT `active: true`
  -> passive-only scanner -> HA couldn't use it for GATT connections.**
  Fixed in the YAML, compiled with the esphome docker container and
  OTA-flashed to the device (esphome compile/upload living-cover.yaml).
- docker-exec scripts CANNOT share HA's running bluetooth manager (the
  single advertisement-subscriber slot per proxy is held by HA): use the
  fc_smarthome.ble_probe / ble_unlock services instead (they run inside HA).
- `fcble/esphome_bridge.py` exists for standalone use (works, but only
  when HA's proxies are disconnected from HA — not the normal case).

### New services in the integration (deployed)
- `fc_smarthome.ble_probe {device_id}` — scan->GATT->handshake, NO unlock,
  logs frames in/out at DEBUG ('FC BLE ->' / 'FC BLE <-'), fires a
  persistent_notification with the result.
- `fc_smarthome.ble_unlock {device_id}` — handshake + FCBleOpenMessage
  (door OPENS).
- Router fix: MACs from the cloud payload are RAW HEX (341727051920);
  `_normalize_mac()` converts to colon form — this was why BLE was never
  reached before (router fell through to cloud 682 every time).
- `_transact_fc` writes use response=False chunks of 20B (FFE1 rejects
  write-with-response: GATT error 3).

### Where the live test stopped (next physical test with the user)
1. GATT connect VIA PROXY: **WORKS** ("HA bluetooth provided ... L5",
   connect succeeded, notify armed).
2. Handshake frame sent (54B, chunked): `FC BLE -> fd003600 e038...`
   correct structure (verified by decrypting our own frame).
3. **No notify response yet** (`FC BLE <-` never fired). One run hit a
   GATT connect timeout instead (lock busy from previous connection).
Next steps when user is at the door:
- run ble_probe WHILE touching the keypad (lock awake+advertising fresh)
- watch for `FC BLE <-` frames; if a frame arrives with cat 2/cmd 8 the
  handshake is answered; check result byte + session key
- if still silent: try alternative identities for the handshake payload
  (deviceuuid vs uid=341727051920 vs empty), and try v1 frames (0xFC start)
- once handshake works: `fc_smarthome.ble_unlock` -> DOOR OPENS
- then wire lock.py async_unlock through router (already local-first)

### Autonomous testing + graceful degradation (2026-09-12 late)

- `tools/ble_test_runner.py` — ONE command runs the whole battery without
  the agent: countdown for the user to touch the keypad, fires the
  ble_probe/ble_unlock services through the HA API, greps the FC BLE log
  frames, and prints a VERDICT. Verified end to end (see session log).
- `lock.py` graceful degradation now:
  BLE (if router+manager exist) -> cloud -> on 682: automatic retries for
  60s (5s interval, so a keypad touch mid-retry can still succeed) ->
  persistent notification with the "press 4 and #" guidance + human error.
- ble_probe now tries THREE handshake identities on separate connections
  (deviceuuid / raw uid / zeros) — the exact 32-byte identity the L5
  expects is still unconfirmed (all three timed out in the last run while
  the lock was asleep).
- Open question for the next live session: the lock does not answer the
  VERIFY_IDENTITY over GATT notify. Frames we send are structurally
  verified (decrypt our own ciphertext = expected plaintext). Ideas:
  (a) the lock only listens when freshly awake — probe right after a
  keypad touch (the runner's countdown exists for this);
  (b) notify subscription race: HA proxies arm notify AFTER connect, but
  the lock may need a first dummy write before responding;
  (c) try v1 framing (0xFC start, no inner len);
  (d) capture the OFFICIAL app doing a BLE open with an HCI snoop while
  the user opens with the app — the definitive diff.



All findings below were verified **live** against the real FC cloud, the
real lock (device `7b120ba58284f360699d44cebaba0a12`, L5-WIFI-QINGKE,
BLE MAC `34:17:27:05:19:20`), and the production Home Assistant instance.

## Environment / access paths (verified)

| Access | How | Status |
|---|---|---|
| FC cloud from dev PC | `fcctl --region eu ...` (repo `.env` has phone/cc/password) | works |
| HA instance | Docker `homeassistant` on host `192.168.2.113` (Proxmox VM "MountainPJ4", root SSH with key from this PC works) | works |
| HA config path | `/docker/homeassistant` on host (mounted as `/config` in container) — Windows SMB share `\\192.168.2.3\docker\homeassistant` works but **stale/backup view, NOT the live host** (real host is `.113`, share points at `.3` which serves an old copy without `fc_smarthome`) | careful |
| HA API | `agy --dangerously-skip-permissions --print` + its `home-assistant` MCP (ha.pj4.duckdns.org, entry loaded, v1.0.0 via HACS) | works |
| Deploy code | `scp` to `root@192.168.2.113:/docker/homeassistant/custom_components/fc_smarthome/` then `docker restart homeassistant` (verified: md5 of deployed files == repo) | works |
| HA reload without full restart | reload entry via HA API/MCP (`homeassistant.config_entries` reload) or `docker restart homeassistant` (only ~20s downtime) | works |

- HA is **HA Container** (no Supervisor), so no SSH add-on; use docker exec
  on `.113` instead. `docker exec homeassistant python3 ...` works.
- The HA MCP can read logs/states/call services but **cannot read arbitrary
  files** in the container.
- The `.secrets` files (`fc_secure_data.json`, `fc_app_privkey.b64`) are
  deployed at `/docker/homeassistant/` (config dir) — integration finds
  them there (config-flow path works, negotiated key acquired on boot).

## Lock hardware facts (from cloud getDevice, verified)

- Model `L5-WIFI-QINGKE`, firmware `Ver:B2.7.3.64`, BLE protocol v6.5
- `enableWifi: true`, `autoWakeUp: false`, `automaticWakeupTime: 0`
- `endpoint: 0`, `shortaddress: 0`, `state: 1`
- `bluetoothKey`/`communicationKey`: `4CADB87095639211A1303639D98E9150`
  (matches DEFAULT_BLE.default_aes_key in endpoints.py — good)
- `dynamicKey`/`noNetPasswordKey`: `fb6c2754a716ba88`
- `wifissid: "PJ4_IoT"` — lock is on a **separate IoT VLAN/SSID**
- `deviceBindUserId`: `2d9cee41d51d4b4d948de24f4fd6bfb6`
- Battery 50%, `lockState` sticks at 0 after last unlock (auto-relock model,
  bolt re-locks itself ~10-15s after each unlock)

## Remote unlock — everything tried (all FAIL with HTTP 682 "null")

`POST /v2/lock/openLock` returns **HTTP 500/682 with encrypted body `null`**
consistently. Verified NOT the cause:

1. Payload shape `{id, token, timestamp}` (exact app shape) — 682
2. Key variants `uuid`/`deviceUuid`/`deviceId` — 682 or conn error
3. Extra header `systime`, `language` — 682
4. **Spoofing the app's `phoneId`** (`<redacted device id from the mitm
   capture>`, full session: handshake+login+validate+openLock) — validate
   OK, openLock 682. → NOT a phoneId/app-identity issue.
5. Full app flow order:
   `getLocalVerifyPassword {id, publicKey, token, timestamp}` (works,
   returns fresh 32-hex `data` each call, NOT RSA-encrypted — the publicKey
   we send gets ignored for the response) → `validateSecurityPassword`
   {password=md5(security pw), id, token, timestamp} (returns
   `{"message":"success","result":1}`) → `openLock` — still 682.
6. Passing the local-verify password / security-md5 inside the openLock
   body (`password` field) — 682.
7. 12 retries over ~2 min (wake-up theory: server would wake the lock via
   WiFi keepalive) — always 682, device `state` never changes.
8. Alternate paths — 404 (decrypted Spring errors):
   `/v2/wifilock/openLock`, `/v2/lock/remoteOpenLock`, `/v2/lock/unlock`.
9. `validateLocalVerifyPassword` — no such path key in our registry but
   exists in APK: `/v2/device/validateLocalVerifyPassword` (untested —
   test next session with that literal path).

### Hypothesis (most likely, needs one more test)

The app's remote open for **WIFI locks** (`iot_device_manage_remoteopen_
wake_wifi_lock_tip` string in the APK) requires the lock to be **online to
the cloud at that moment**. The L5 WiFi lock sleeps (`autoWakeUp: false`)
and only keeps a short-link when the app is on the same LAN. The app
probably: (a) wakes the lock over **BLE first** (that's why the mitm capture
never shows a successful openLock — no openLock request exists at all in
the whole capture!), or (b) requires the **LAN channel** (Alink/CoAP or a
WiFi TCP port) to deliver the open command.

Key evidence from the mitm capture (`fc_traffic.jsonl`, real app traffic):
- 44 decrypted requests; **ZERO openLock calls**. The app NEVER opened the
  lock remotely during the capture. All it did: loginToken storm (1827
  retries = our replay tests, ignore), getDeviceList, getDevice,
  getLockMessageList, getLockUserList/v2, getLockUser/v2,
  getLocalVerifyPassword ×2, validateSecurityPassword ×2.
- The two `validateSecurityPassword` calls carry a **static md5**
  `<redacted>` (identical across days) = the
  account's **security password** md5. We have it and it validates fine.
- Strings in `d1.dex`: `remoteOpenLock onFailed ----` / `onSuccess` are
  **JS (React control page)** logs → remote open goes through the
  smartlock **jssdk** bridge (BLE/LAN), not plain cloud HTTP.

### LAN search for the lock (done, negative)

- HA host `.113` sees LAN `192.168.0.0/22` (VLANs .0/.1/.2/.3 all bridged).
- Full TCP port scan (1-65535) of every live host in `.3.x` (IoT VLAN) and
  the unidentified `.1.51`: only `192.168.3.62:80` (an ESPHome device) and
  `192.168.3.51:8081` (tproxy, no HTTP response) are open. **No lock
  listening ports (8060/9999/8666/5683) found anywhere.**
- arp-scan full /22: no device with the lock's MAC OUI `34:17:27` on WiFi.
  → **The lock's WiFi is either asleep or on an SSID/VLAN not bridged to
  the HA host** (SSID `PJ4_IoT`; the router may isolate it). Only
  Espressif devices seen: `192.168.3.62` (MAC c8:f0:9e:de:3a:b7) and
  `192.168.3.51` (3c:61:05:83:73:2b) — neither is the lock (lock BLE MAC
  34:17:27:05:19:20; WiFi MAC may differ — 34:17:27 OUI belongs to the
  lock vendor; nothing with that OUI answered ARP).
- Conclusion so far: **cloud openLock is genuinely broken/blocked server-
  side (682 = vendor "lock not reachable/awake" most likely), and the LAN
  channel is not reachable from the HA host.** BLE from HA host is not
  possible either (it's a VM without BT). The realistic remote-unlock
  paths left: (1) find which VLAN `PJ4_IoT` maps to and get the HA host
  or an ESP/bridge into it; (2) BLE proxy (ESPHome Bluetooth proxy) near
  the lock; (3) accept cloud-unlock only works right after the lock is
  awake (e.g. right after a bell/keypress — test: press bell, then
  openLock within seconds).

**682 semantics:** 672 = rate limit. 682 observed = server-side "null"
error right after successful validate → vendor backend cannot reach the
lock (it's asleep/not cloud-connected). This matches the app UX of
"waking..." dialogs for wifi locks.

## Ring bell — verified behavior

- `bell` endpoint `/v2/wifilock/setDoorBellVolume` returns
  `API result 0: System error` (result 0, not 1) → it's a settings
  endpoint (volume), NOT a ring command. No cloud "ring" endpoint exists
  in the APK string table. Physical bell rings (button press on lock)
  DO appear in cloud history as `lock.message.lock.bell` — that's the only
  bell signal we get (poll-based).
- Ring-bell BUTTON in HA therefore can never work via cloud; it should be
  re-labeled/hidden or trigger via BLE (unavailable) — current graceful
  degradation is correct behavior, message is accurate.

## History / events — verified behavior + bugs found

- Full history: `getLockMessageList/v2` with `fromTime=0` returns ~1 year
  (378+ events). Narrow `fromTime` windows (ms epoch) return nothing —
  always fetch broad + slice locally (already fixed in client.py).
- `import_history` service works: 378 fetched, 0 imported (dedup — they
  were already in the ring buffer), 7 battery stats imported into
  recorder via `async_add_external_statistics` (works, no table error).
- **BUG (fixed plan):** `doorbell_last_ring` sensor shows the OLDEST bell
  (`2026-09-05T09:52:36`) instead of newest (`2026-09-11T21:44:55`) because
  on first sync the coordinator processes events oldest-first and the
  per-event loop overwrites `doorbell_last_ring` with each newer... no —
  actually `_process_new_events` fires events in list order (newest-first
  from cloud) but `import_history` replays sorted oldest-first, so the
  LAST processed = newest for access_log ordering but
  `doorbell_last_ring[device] = ev.timestamp or now()` — during import the
  final value should be newest... it ended up 09-05 → the bug: on the
  normal polling path `_process_new_events` sets `last_event[dev] =
  fresh[0]` (newest) fine, but `doorbell_last_ring` is only set inside
  `_fire_event` per event — during the initial 26-event burst the FIRST
  bell in `fresh` (which is newest-first order → 09-05 is the oldest
  bell, appears LAST) — wait, verified state shows 09-05 stuck while
  newer bells exist (09-08 ×4, 09-11) → the newer bells arrived via
  normal polling AFTER load and still didn't update it. Root cause:
  `_process_new_events` is called with `events` (newest-first), fires
  `_fire_event(ev)` for each in list order — bells update
  `doorbell_last_ring` each time — so after the 09-11 bell (21:44:55
  arrived 00:51-ish) the sensor should read 09-11... it reads 09-05
  because the sensor entity caches native_value only on coordinator
  listener update, and `doorbell_last_ring` dict IS updated... Actually
  the 09-11 bell arrived at 00:51:27+00:00 which is AFTER the container
  restart at 20:33? No — 2026-09-11T21:44:55 UTC bell is within the
  26-event initial burst (fired 20:33:41 local = 18:33 UTC). The state
  was written at 18:33:49 and never again because no NEW bell since.
  The sensor shows 09-05 because in the initial burst, events are fired
  NEWEST-FIRST... the final `_fire_event` overwrite wins → last fired
  = oldest = 09-05 09:52:36. **FIX: `doorbell_last_ring`/`ring_count`
  must be computed from the freshest event, not "last fired" — or fire
  events oldest-first.** Same class of bug affects nothing else.
- `access_log` ordering is correct (newest-first, `appendleft`).
- Event dedup key includes `str(ev.raw.get("id",""))` — cloud events have
  unique ids per event; good.
- Coordinator polls history with `from_ms = now - 7d` and `limit=30`
  — works; new events picked up within one poll cycle (~30s).

### Known misleading/missing params in HA (to fix)

1. `sensor.*_last_unlock_user/method/time` stay `unknown` forever with
   cloud-only setup: they're only populated from the **BLE** sync path.
   FIX: populate from cloud events (`last_event` UNLOCKED → user/method/
   timestamp). The cloud history HAS user names ("Me", "Karol 2",
   "Juanma 220993", "Tipo 2 - Abuelos") and method hints in messageKey.
2. `sensor.*_firmware_version` shows `unknown`: cloud device payload has
   `firmwareversion: "Ver:B2.7.3.64"` but code reads
   `capabilities.get("firmwareVersion")` (wrong key case — payload uses
   `firmwareversion`; the capability copy loop uses the right key but
   the sensor checks `firmwareVersion`). FIX: read `firmwareversion`.
3. `sensor.*_signal` unknown (cloud has no RSSI; BLE-only) — acceptable,
   could hide or mark unavailable when no BLE.
4. `binary_sensor.*_door` shows `off` always: cloud `doorState` exists
   (false) — works but is only refreshed every poll; fine.
5. Tamper/door_open_long/motor_error/low_battery/child_lock binary
   sensors all `unknown`: `get_device_status` never sets them from raw
   fields (`alarmLockNotClosed` → door_open_long is set only if truthy;
   others like `childLock` (0), `antiLock`, `defendSwitch` exist in raw
   but aren't mapped). FIX: map `childLock`→child_lock,
   `alarmLockNotClosed`→door_open_long, and treat raw bools properly
   (they're 0/1 ints — `bool(0)` = False would actually be *shown* as
   off, but code returns None when raw key absent from LockStatus
   because get_device_status only sets door_open_long conditionally).
   Low battery: `lock.message.lower.battery` events exist in history →
   last-alarm/low-battery can derive from recent events.
6. `switch.child_lock` state unknown: same mapping gap.
7. `event.smart_lock_events` works; triggers fire on new events
   (verified `unlocked` at 18:38).
8. `lock.smart_lock` lock/unlock UI: unlock fails with HomeAssistantError
   (correct now), but **optimistically sets state to unlocked before the
   command runs** — if the command fails, HA shows wrong state until
   next poll. FIX: don't pre-set, or roll back on failure.
9. `update.*` entity: HACS update for the repo, `off` — fine.

## History import on account add (config flow)

Current behavior: config flow stores `devices` snapshot but does **NOT**
auto-backfill history; the `import_history` service must be called
manually. User wants: when account is added, import full history + sync
with existing data automatically.
PLAN (implemented this session):
- In `async_setup_entry` after first refresh, schedule a one-shot
  backfill task (guarded by a flag in entry data so it runs once per
  entry) that: fetches full history (`from_ms=0`), replays through
  `_process_new_events_single` oldest-first, imports battery stats,
  primes `last_unlock_*` sensors from the newest UNLOCKED event, and
  primes bell last-ring/count. Also expose `days` option.

## Bell count semantics

`doorbell_ring_count` = count of bell events processed this session
(starts at 6 after initial burst of 26 events containing 6 bells) —
resets on restart. After the last_ring fix, keep count as-is but derive
initial value from history so restarts don't zero it (derive = number of
bell events in the retained access log).

## Security notes

- `validateSecurityPassword` md5 (`<redacted>`) = md5 of the account's
  security password (not the login password; unknown plaintext, but the
  md5 validates — store as secret for future flows).
- Login password md5 = `<redacted>` (credentials live only in `.env` /
  the HA config entry — never in docs or git).
- Repo `.env` has credentials (gitignored) — fine locally, never commit.
- HA REST long-lived token for the MCP: stored in agy MCP config (bearer
  JWT); not in repo.

## Files/artifacts from this session (temp, outside repo)

- `C:\Users\Juanm\AppData\Local\Temp\opencode\fc_unlock_probe*.py` —
  unlock probes 1-8 (all negative results documented above)
- `...\fc_find_lock_lan.py`, `fc_lan_scan.py`, `fc_full_portscan.py` —
  LAN discovery scripts (negative)
- Mitm capture (from 2026-09-08 session, reused):
  `C:\Users\Juanm\AppData\Local\Temp\opencode\mitm\fc_traffic.jsonl`
  (31MB, 44 real app reqs decrypted in `decrypted.json`)

## Next steps (queued)

1. Try `/v2/device/validateLocalVerifyPassword` (literal path) with the
   fresh local-verify pw → then openLock. **DONE 2026-09-12 01:00:
   HTTP 200 result:0 "Verfication of device manage failed"** — the
   endpoint exists but the fresh verify pw is not the right credential
   (it likely needs the manage password or the RSA-wrapped variant).
2. Test "awake window": ring the physical bell / unlock by fingerprint,
   then IMMEDIATELY (within ~30s) send openLock. **RAN TWICE (10-min
   windows, 2026-09-11 23:20 and 23:35 local): NO wake events appeared
   in cloud history at all — the user did not/could not trigger the
   bell during the windows. Test still PENDING a live wake.**
3. Fix the entity bugs listed above (last_ring order, firmware key,
   child_lock mapping, last_unlock_* from cloud, optimistic unlock
   rollback) — code changes in this repo, deploy via scp+restart.
4. Auto-backfill history on account add (see plan above).
5. Ask user about `PJ4_IoT` VLAN / whether HA can reach it (or get an
   ESPHome BT proxy near the lock for the BLE channel).

## Session update 2026-09-12 ~01:10 (UTC+2) — FIXES DEPLOYED & VERIFIED

All entity bugs fixed, deployed to HA (scp to root@192.168.2.113:/docker/
homeassistant/custom_components/fc_smarthome/ + docker restart) and
verified live via agy MCP:

| Entity | Before | After (verified) |
|---|---|---|
| last_doorbell_ring | 2026-09-05 (oldest, bug) | `2026-09-11T21:44:55Z` ✓ |
| last_unlock_user/method/time | unknown | `Karol 2` / `finger` / `00:51:27Z` ✓ |
| firmware_version | unknown | `Ver:B2.7.3.64` ✓ |
| child_lock switch | unknown | `off` ✓ |
| low_battery | unknown | `off` (from deviceCategory.lowbattery=10 threshold vs battery=50) ✓ |
| door_open_long | unknown | `off` (alarmLockNotClosed) ✓ |
| doorbell_ring_count | reset on restart | derives from retained log (10 at boot; in-memory count continues) |
| event methods | unknown ×336 | 320/378 resolved: 320 finger, 9 card, 4 remote, 2 password, 1 app (cross-ref getLockUserList user types) ✓ |
| unlock optimistic state | stuck unlocked 10s after failed unlock | rolled back immediately + human error message ✓ |
| history on account add | manual service call only | auto-backfill runs once per entry (`history_backfilled` flag) — verified "FC SmartHome history backfill complete" in logs ✓ |

Code changes in this session (repo, 47/47 pytest passing):
- coordinator.py: oldest-first firing, newest-wins state tracking,
  `prime_from_history()`, user-cache preload in poll cycle
- client.py: status flag mapping (childLock/alarmLockNotClosed/lowbattery
  threshold), `_ensure_user_cache()`, `_enrich_event_methods()` (user
  cross-ref), comment documenting the 682 sleep limitation on unlock
- lock.py: optimistic rollback + human 682 error
- sensor.py: firmware key fix
- __init__.py: auto-backfill task + mean_type metadata fix
- tools/live_test_suite.py (new, 7 stages, verified vs real cloud)
- tools/unlock_awake_window.py (new, the decisive awake-window test)

Deploy gotcha learned: `scp custom_components/fc_smarthome/*.py` only
syncs top-level; the `api/` subdir must be synced separately or HA runs
a MIXED old/new codebase (caused a confusing
`'FcClient' object has no attribute '_ensure_user_cache'`). Full sync:
`scp -r custom_components/fc_smarthome/* root@192.168.2.113:/docker/
homeassistant/custom_components/fc_smarthome/` + clear `__pycache__`.

Remaining for the joint session (see docs/TEST-PLAN-2026-09-12.md):
- **Awake-window remote unlock test** (decisive; script ready)
- Bell-press → HA reaction timing check
- Fresh account add (delete+re-add entry) to watch auto-backfill live
- If awake-window unlock still 682: capture official-app remote unlock
  with mitmproxy and diff (tooling in %TEMP%\opencode\mitm\)


- User CONFIRMED: no successful remote unlock has EVER happened tonight —
  the 18:30/18:37 "unlocked→locked (10s)" logbook entries were HA's
  optimistic state bug: `async_unlock` sets unlocked optimistically,
  the command fails (682), then the next poll restores locked. Also the
  18:37:52 "Me" cloud event was a FINGERPRINT unlock at the door, not
  remote.
- `validateLocalVerifyPassword` (literal path) exists: returns
  `result:0 "Verfication of device manage failed"` with the fresh
  local-verify pw — endpoint live, credential wrong (needs manage
  password? RSA-wrapped pw?).
- openLock keeps returning 500/682 `null` after every variation tried
  (8+ probes). Strong hypothesis stands: vendor cloud cannot relay
  the open because the WiFi lock is asleep/not cloud-connected, and
  the official app also cannot remote-open right now (user should try
  once from the app to confirm — if the app also fails, this is a
  server/lock-sleep limitation, NOT an integration bug; if the app
  succeeds, capture that app session with mitmproxy to diff).
- Awake-window watcher script kept at
  `C:\Users\Juanm\AppData\Local\Temp\opencode\fc_awake_window_test.py`
  — re-run and press the bell on the lock when prompted.

