"""Shared constants usable by both the CLI and the HA integration.

Kept independent of Home Assistant so `fcctl` can import it standalone.
The HA component re-exports these from its own const.py.
"""

DOMAIN = "fc_smarthome"

PLATFORMS = ["lock", "sensor", "binary_sensor", "switch", "button", "event"]

CONF_EMAIL = "email"
CONF_PASSWORD = "password"
CONF_TOKEN = "token"
CONF_FAMILY_ID = "family_id"
CONF_REGION = "region"
CONF_POLL_INTERVAL = "poll_interval"
CONF_LOCAL_BLE = "local_ble"
CONF_LOCAL_LAN = "local_lan"
CONF_ENDPOINTS_FILE = "endpoints_file"
CONF_SECURE_DATA = "secure_data"
CONF_PRIVATE_KEY = "private_key"
CONF_COUNTRY_CODE = "country_code"


DEFAULT_POLL_INTERVAL = 30

ATTR_DEVICE_ID = "device_id"
ATTR_METHOD = "method"
ATTR_USER = "user"
ATTR_USER_ID = "user_id"
ATTR_REMOTE = "remote"
ATTR_BATTERY = "battery"
ATTR_TIMESTAMP = "timestamp"
ATTR_EVENT_TYPE = "event_type"
ATTR_LAST_EVENT = "last_event"

EVENT_FC_EVENT = "fc_smarthome_event"
EVENT_FC_CARD = "fc_smarthome_card"

SERVICE_ADD_USER = "add_user"
SERVICE_DELETE_USER = "delete_user"
SERVICE_RENAME_USER = "rename_user"
SERVICE_ENROLL_FINGERPRINT = "enroll_fingerprint"
SERVICE_FETCH_HISTORY = "fetch_history"
SERVICE_IMPORT_HISTORY = "import_history"
SERVICE_RING_BELL = "ring_bell"
SERVICE_BEEP = "locate_device"
SERVICE_SET_CHILD_LOCK = "set_child_lock"
SERVICE_BLE_UNLOCK = "ble_unlock"
SERVICE_BLE_PROBE = "ble_probe"

# devStatus bitmask decode. Hypothesis derived from sibling Alibaba-Cloud-style
# lock firmware; bit assignments must be confirmed via tools/HARVEST.md captures.
DEVICE_STATUS_MASKS = {
    "locked": 0x0004,
    "motor_moving": 0x0001,
    "door_open": 0x0008,
    "door_open_long": 0x0010,
    "tamper": 0x0020,
    "low_battery": 0x0040,
    "child_lock": 0x0080,
    "motor_error": 0x0100,
    "latch_open": 0x0200,
}

USER_TYPE_INT_MAP = {
    0: "password",
    1: "finger",
    2: "card",
    3: "nfc",
    4: "remote",
    5: "key",
    6: "face",
    7: "temp",
}

UNLOCK_METHOD_LABELS = {
    0: "password",
    1: "finger",
    2: "card",
    3: "nfc",
    4: "remote",
    5: "key",
    6: "face",
    9: "app",
}
