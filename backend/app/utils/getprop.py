"""Parsers for Android property files (getprop output and build.prop)."""

import re


def parse_getprop_txt(text: str) -> dict[str, str]:
    """Parse `adb shell getprop` output format: [key]: [value]."""
    result: dict[str, str] = {}
    pattern = re.compile(r"^\[(.+?)\]: \[(.*)?\]$")
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        m = pattern.match(line)
        if m:
            result[m.group(1)] = m.group(2) or ""
    return result


def parse_build_prop(text: str) -> dict[str, str]:
    """Parse build.prop format: key=value, skipping comments and blank lines."""
    result: dict[str, str] = {}
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        if "=" in line:
            key, _, value = line.partition("=")
            result[key.strip()] = value.strip()
    return result


def extract_device_metadata(props: dict[str, str]) -> dict:
    """Extract structured device metadata from a parsed properties dict."""
    api_str = props.get("ro.build.version.sdk", "0")
    try:
        api_level: int | None = int(api_str) if api_str else None
    except (ValueError, TypeError):
        api_level = None
    if api_level == 0:
        api_level = None

    flash_locked = props.get("ro.boot.flash.locked")
    if flash_locked == "0":
        bootloader_state = "unlocked"
    elif flash_locked == "1":
        bootloader_state = "locked"
    else:
        bootloader_state = "unknown"

    security_posture_raw = {
        "ro_secure": props.get("ro.secure"),
        "ro_debuggable": props.get("ro.debuggable"),
        "ro_adb_secure": props.get("ro.adb.secure"),
        "crypto_state": props.get("ro.crypto.state"),
        "verified_boot": props.get("ro.boot.verifiedbootstate"),
        "selinux": props.get("ro.boot.selinux"),
    }
    security_posture = {k: v for k, v in security_posture_raw.items() if v is not None}

    return {
        "device_model": props.get("ro.product.model"),
        "manufacturer": props.get("ro.product.brand"),
        "android_version": props.get("ro.build.version.release"),
        "api_level": api_level,
        "security_patch": props.get("ro.build.version.security_patch"),
        "build_fingerprint": props.get("ro.build.fingerprint"),
        "chipset": (
            props.get("ro.board.platform")
            or props.get("ro.mediatek.platform")
            or props.get("ro.hardware.chipname")
        ),
        "bootloader_state": bootloader_state,
        "security_posture": security_posture,
    }
