#!/usr/bin/env bash
set -Eeuo pipefail
[[ $# -eq 1 ]] || { echo "usage: $0 PATH_TO_DOT_CONFIG" >&2; exit 2; }
CONFIG="$1"
[[ -f "$CONFIG" ]] || { echo "missing config: $CONFIG" >&2; exit 2; }

set_config() {
  local key="$1" value="$2"
  sed -i -e "/^${key}=/d" -e "/^# ${key} is not set$/d" "$CONFIG"
  echo "${key}=${value}" >> "$CONFIG"
}
set_config CONFIG_VIRTIO_MMIO y
set_config CONFIG_VIRTIO_BLK y
set_config CONFIG_EXT4_FS y
set_config CONFIG_SERIAL_8250 y
set_config CONFIG_SERIAL_8250_CONSOLE y
set_config CONFIG_DEVTMPFS y
set_config CONFIG_DEVTMPFS_MOUNT y
