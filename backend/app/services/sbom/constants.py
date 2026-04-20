"""Module-level constants for SBOM detection strategies.

Centralised here so every strategy module imports them from one place —
CLAUDE.md Rule #11 (constants-outside-split-file → NameError at runtime)
is avoided when the monolith is deleted in the cut-over.

Constants:

- ``MAX_BINARIES_SCAN``, ``MAX_BINARY_READ``, ``MAX_LIBC_READ``: byte-read
  caps for binary scanning.
- ``CPE_VENDOR_MAP``: component name → (CPE vendor, CPE product) lookup.
- ``VERSION_PATTERNS``: (component_name, compiled-regex) list matched
  against binary strings.
- ``_GENERIC_EXCLUDE_NAMES`` / ``_GENERIC_SEMVER_RE``: used by the generic
  fallback binary detection.
- ``SONAME_COMPONENT_MAP``: library SONAME → component name alias.
- ``FIRMWARE_MARKERS``: distro marker-file lookups.
- ``KNOWN_SERVICE_RISKS``: daemon name → risk tier.

Plus the ``IdentifiedComponent`` dataclass, which is the shared unit of
currency between strategies and ``SbomService``.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

MAX_BINARIES_SCAN = 500
MAX_BINARY_READ = 256 * 1024  # 256KB for strings extraction
MAX_LIBC_READ = 512 * 1024  # 512KB — C library binaries are large

# Well-known vendor:product mappings for CPE construction
CPE_VENDOR_MAP: dict[str, tuple[str, str]] = {
    # Core system
    "busybox": ("busybox", "busybox"),
    "glibc": ("gnu", "glibc"),
    "libc": ("gnu", "glibc"),
    "uclibc": ("uclibc", "uclibc"),
    "musl": ("musl-libc", "musl"),
    "bash": ("gnu", "bash"),
    # SSL/TLS & crypto
    "openssl": ("openssl", "openssl"),
    "libssl": ("openssl", "openssl"),
    "libcrypto": ("openssl", "openssl"),
    "wolfssl": ("wolfssl", "wolfssl"),
    "libwolfssl": ("wolfssl", "wolfssl"),
    "mbedtls": ("arm", "mbed_tls"),
    "libmbedtls": ("arm", "mbed_tls"),
    "libmbedcrypto": ("arm", "mbed_tls"),
    "gnutls": ("gnu", "gnutls"),
    "libgnutls": ("gnu", "gnutls"),
    "libsodium": ("libsodium_project", "libsodium"),
    "libgcrypt": ("gnupg", "libgcrypt"),
    "libnettle": ("gnu", "nettle"),
    # Web servers
    "nginx": ("f5", "nginx"),
    "lighttpd": ("lighttpd", "lighttpd"),
    "apache": ("apache", "http_server"),
    "httpd": ("apache", "http_server"),
    "mini_httpd": ("acme", "mini_httpd"),
    "uhttpd": ("openwrt", "uhttpd"),
    "goahead": ("embedthis", "goahead"),
    "boa": ("boa", "boa_web_server"),
    "thttpd": ("acme", "thttpd"),
    "mongoose": ("cesanta", "mongoose"),
    # SSH
    "dropbear": ("matt_johnston", "dropbear"),
    "openssh": ("openbsd", "openssh"),
    # DNS
    "dnsmasq": ("thekelleys", "dnsmasq"),
    "unbound": ("nlnetlabs", "unbound"),
    # Network services
    "curl": ("haxx", "curl"),
    "libcurl": ("haxx", "curl"),
    "wget": ("gnu", "wget"),
    "hostapd": ("w1.fi", "hostapd"),
    "wpa_supplicant": ("w1.fi", "wpa_supplicant"),
    "openvpn": ("openvpn", "openvpn"),
    "samba": ("samba", "samba"),
    "mosquitto": ("eclipse", "mosquitto"),
    "avahi": ("avahi", "avahi"),
    # Firewall / netfilter
    "iptables": ("netfilter", "iptables"),
    "ip6tables": ("netfilter", "iptables"),
    "nftables": ("netfilter", "nftables"),
    # FTP / SNMP / UPnP
    "proftpd": ("proftpd", "proftpd"),
    "vsftpd": ("beasts", "vsftpd"),
    "miniupnpd": ("miniupnp_project", "miniupnpd"),
    "ntpd": ("ntp", "ntp"),
    "netatalk": ("netatalk", "netatalk"),
    # Bootloader
    "uboot": ("denx", "u-boot"),
    "u-boot": ("denx", "u-boot"),
    # Utility libraries
    "zlib": ("zlib", "zlib"),
    "sqlite": ("sqlite", "sqlite"),
    "libjpeg": ("ijg", "libjpeg"),
    "libpng": ("libpng", "libpng"),
    "lua": ("lua", "lua"),
    "perl": ("perl", "perl"),
    "python": ("python", "python"),
    "json-c": ("json-c_project", "json-c"),
    "libxml2": ("xmlsoft", "libxml2"),
    "pcre": ("pcre", "pcre"),
    "expat": ("libexpat_project", "libexpat"),
    "dbus": ("freedesktop", "dbus"),
    "readline": ("gnu", "readline"),
    "ncurses": ("gnu", "ncurses"),
    # OpenWrt ecosystem
    "ubus": ("openwrt", "ubus"),
    "libubox": ("openwrt", "libubox"),
    "uci": ("openwrt", "uci"),
    # Compiler / toolchain
    "gcc": ("gnu", "gcc"),
    "uclibc-ng": ("uclibc", "uclibc"),
    # Network tools
    "net-snmp": ("net-snmp", "net-snmp"),
    "iproute2": ("iproute2_project", "iproute2"),
    "pppd": ("samba", "ppp"),
    "libnl": ("infradead", "libnl"),
    # Logging
    "syslog-ng": ("balabit", "syslog-ng"),
    # IoT protocols
    "libcoap": ("libcoap", "libcoap"),
    "lwip": ("lwip_project", "lwip"),
    "contiki": ("contiki-os", "contiki"),
    "contiki-ng": ("contiki-ng", "contiki-ng"),
    "tinydtls": ("eclipse", "tinydtls"),
    "mbed-os-connectivity": ("arm", "mbed_os"),
    "mbed-os": ("arm", "mbed_os"),
    # TR-069/CWMP
    "cwmpd": ("cwmp", "cwmpd"),
    # Bootloaders (additional)
    "grub": ("gnu", "grub2"),
    "grub2": ("gnu", "grub2"),
    "coreboot": ("coreboot", "coreboot"),
    "barebox": ("barebox", "barebox"),
    "arm-trusted-firmware": ("arm", "arm-trusted-firmware"),
    "atf": ("arm", "arm-trusted-firmware"),
    "bl1": ("arm", "arm-trusted-firmware"),
    "bl2": ("arm", "arm-trusted-firmware"),
    "bl31": ("arm", "arm-trusted-firmware"),
    "edk2": ("tianocore", "edk2"),
    "tianocore": ("tianocore", "edk2"),
    # Android framework
    "android": ("google", "android"),
    "webview": ("google", "android"),
    "android-runtime": ("google", "android"),
    # MediaTek SoC libraries
    "libmtk": ("mediatek", "mt_system_software"),
    "libmtk_bsg": ("mediatek", "mt_system_software"),
    "libmtk_vpu": ("mediatek", "mt_system_software"),
    "libnvram": ("mediatek", "mt_system_software"),
    "libcam_utils": ("mediatek", "mt_system_software"),
    "mtk-ccci": ("mediatek", "mt_system_software"),
    "mediatek-telephony": ("mediatek", "mt_system_software"),
    # Qualcomm SoC libraries
    "libqmi": ("qualcomm", "mdm"),
    "libqmi_cci": ("qualcomm", "mdm"),
    "libqmi_csi": ("qualcomm", "mdm"),
    "libdiag": ("qualcomm", "mdm"),
    "libqti": ("qualcomm", "mdm"),
    "libadsprpc": ("qualcomm", "mdm"),
    "libcdsprpc": ("qualcomm", "mdm"),
    "adreno": ("qualcomm", "adreno_gpu"),
    "libgsl": ("qualcomm", "adreno_gpu"),
    "qca-wifi": ("qualcomm", "qca_wifi_firmware"),
    # Industrial protocols
    "libmodbus": ("libmodbus", "libmodbus"),
    "open62541": ("open62541", "open62541"),
    "libopen62541": ("open62541", "open62541"),
    "opcua": ("opcfoundation", "ua-.net_standard"),
    "bacnet": ("bacnet", "bacnet_stack"),
    "libcanopen": ("canopen", "canopen"),
    # Additional network / embedded
    "libevent": ("libevent_project", "libevent"),
    "libev": ("libev_project", "libev"),
    "libuv": ("libuv_project", "libuv"),
    "protobuf": ("google", "protobuf"),
    "grpc": ("grpc", "grpc"),
    "libmicrohttpd": ("gnu", "libmicrohttpd"),
    "lldpd": ("lldpd_project", "lldpd"),
    "snmpd": ("net-snmp", "net-snmp"),
    "chrony": ("chrony_project", "chrony"),
    # Bluetooth / wireless
    "bluez": ("bluez", "bluez"),
    "libbluetooth": ("bluez", "bluez"),
    "iw": ("kernel", "iw"),
    "wireless-tools": ("hewlett_packard_enterprise", "wireless_tools"),
}

# Regex patterns for binary version string extraction
VERSION_PATTERNS: list[tuple[str, re.Pattern]] = [
    ("busybox", re.compile(rb"BusyBox v(\d+\.\d+(?:\.\d+)?)")),
    ("openssh", re.compile(rb"OpenSSH[_ ](\d+\.\d+(?:p\d+)?)")),
    ("dropbear", re.compile(rb"dropbear[_ ](\d+\.\d+(?:\.\d+)?)")),
    ("lighttpd", re.compile(rb"lighttpd/(\d+\.\d+\.\d+)")),
    ("dnsmasq", re.compile(rb"dnsmasq-(\d+\.\d+(?:\.\d+)?)")),
    ("curl", re.compile(rb"curl/(\d+\.\d+\.\d+)")),
    ("wget", re.compile(rb"GNU Wget (\d+\.\d+(?:\.\d+)?)")),
    ("nginx", re.compile(rb"nginx/(\d+\.\d+\.\d+)")),
    ("openssl", re.compile(rb"OpenSSL (\d+\.\d+\.\d+[a-z]*)")),
    ("samba", re.compile(rb"Samba (\d+\.\d+\.\d+)")),
    ("hostapd", re.compile(rb"hostapd v(\d+\.\d+(?:\.\d+)?)")),
    ("wpa_supplicant", re.compile(rb"wpa_supplicant v(\d+\.\d+(?:\.\d+)?)")),
    ("miniupnpd", re.compile(rb"miniupnpd[/ ](\d+\.\d+(?:\.\d+)?)")),
    ("proftpd", re.compile(rb"ProFTPD (\d+\.\d+\.\d+)")),
    ("vsftpd", re.compile(rb"vsftpd: version (\d+\.\d+\.\d+)")),
    ("avahi", re.compile(rb"avahi-daemon (\d+\.\d+\.\d+)")),
    ("ntpd", re.compile(rb"ntpd (\d+\.\d+\.\d+(?:p\d+)?)")),
    ("mini_httpd", re.compile(rb"mini_httpd/(\d+\.\d+(?:\.\d+)?)")),
    ("lua", re.compile(rb"Lua (\d+\.\d+\.\d+)")),
    ("sqlite", re.compile(rb"SQLite (\d+\.\d+\.\d+)")),
    # C library
    ("glibc", re.compile(rb"GNU C Library[^\n]*version (\d+\.\d+(?:\.\d+)?)")),
    ("glibc", re.compile(rb"stable release version (\d+\.\d+(?:\.\d+)?)")),
    ("uclibc-ng", re.compile(rb"uClibc(?:-ng)? (\d+\.\d+\.\d+)")),
    ("musl", re.compile(rb"musl libc (\d+\.\d+\.\d+)")),
    # GCC / toolchain
    ("gcc", re.compile(rb"GCC: \([^)]*\) (\d+\.\d+\.\d+)")),
    # Bootloader
    ("u-boot", re.compile(rb"U-Boot (\d{4}\.\d{2}(?:-\S+)?)")),
    ("u-boot", re.compile(rb"U-Boot SPL (\d{4}\.\d{2}(?:-\S+)?)")),
    # Network tools
    ("iptables", re.compile(rb"iptables v(\d+\.\d+\.\d+)")),
    ("iproute2", re.compile(rb"iproute2[/-](\d+\.\d+(?:\.\d+)?)")),
    ("pppd", re.compile(rb"pppd (\d+\.\d+\.\d+)")),
    ("net-snmp", re.compile(rb"NET-SNMP (\d+\.\d+\.\d+)")),
    ("syslog-ng", re.compile(rb"syslog-ng (\d+\.\d+\.\d+)")),
    # Libraries (content-based extraction)
    ("zlib", re.compile(rb"(?:zlib |inflate )(\d+\.\d+\.\d+(?:\.\d+)?)")),
    ("libpng", re.compile(rb"libpng[- ](\d+\.\d+\.\d+)")),
    ("libxml2", re.compile(rb"libxml2[- ](\d+\.\d+\.\d+)")),
    ("pcre", re.compile(rb"PCRE (\d+\.\d+(?:\.\d+)?)")),
    ("expat", re.compile(rb"expat_(\d+\.\d+\.\d+)")),
    ("libjpeg", re.compile(rb"(?:libjpeg|JPEG[- ]library)[- ](\d+[a-z]?(?:\.\d+)*)")),
    ("json-c", re.compile(rb"json-c[/ ](\d+\.\d+(?:\.\d+)?)")),
    ("dbus", re.compile(rb"D-Bus (\d+\.\d+\.\d+)")),
    # Additional patterns
    ("apache", re.compile(rb"Apache/(\d+\.\d+\.\d+)")),
    ("uhttpd", re.compile(rb"uhttpd[/ ]v?(\d+\.\d+(?:\.\d+)?)")),
    ("goahead", re.compile(rb"GoAhead[/ -](\d+\.\d+\.\d+)")),
    ("openvpn", re.compile(rb"OpenVPN (\d+\.\d+\.\d+)")),
    ("wolfssl", re.compile(rb"wolfSSL (\d+\.\d+\.\d+)")),
    ("mbedtls", re.compile(rb"mbed TLS (\d+\.\d+\.\d+)")),
    ("unbound", re.compile(rb"unbound (\d+\.\d+\.\d+)")),
    ("mosquitto", re.compile(rb"mosquitto[/ ](\d+\.\d+\.\d+)")),
    ("boa", re.compile(rb"Boa/(\d+\.\d+\.\d+)")),
    ("thttpd", re.compile(rb"thttpd/(\d+\.\d+(?:\.\d+)?)")),
    ("mongoose", re.compile(rb"Mongoose[/ ](\d+\.\d+(?:\.\d+)?)")),
]

# Names that should NOT be detected by the generic fallback.  These are
# library / toolchain identifiers whose version strings appear inside many
# unrelated binaries (symbol version requirements, copyright notices, …).
GENERIC_EXCLUDE_NAMES: frozenset[str] = frozenset([
    "glibc", "libc", "gcc", "linux", "openssl", "libssl", "libcrypto",
    "libpthread", "musl", "uclibc", "ld-linux", "libgcc", "libstdc++",
    "libm", "libdl", "librt", "libz", "libpng", "libxml2", "zlib",
    "glib", "pcre",
])

# Pre-compiled generic version regex: matches "{name} {version}" or
# "{name}/{version}" or "{name} v{version}" at a word boundary.
GENERIC_SEMVER_RE = re.compile(
    rb"\b(\d+\.\d+(?:\.\d+)?(?:[a-z]\d*)?)\b"
)

# Library SONAME -> component name mapping for well-known libraries
SONAME_COMPONENT_MAP: dict[str, str] = {
    # SSL/TLS & crypto
    "libssl": "openssl",
    "libcrypto": "openssl",
    "libwolfssl": "wolfssl",
    "libmbedtls": "mbedtls",
    "libmbedcrypto": "mbedtls",
    "libgnutls": "gnutls",
    "libsodium": "libsodium",
    "libgcrypt": "libgcrypt",
    "libnettle": "nettle",
    # Utility libraries
    "libcurl": "curl",
    "libz": "zlib",
    "libsqlite3": "sqlite",
    "libpng": "libpng",
    "libpng16": "libpng",
    "libjpeg": "libjpeg",
    "liblua": "lua",
    "libjson-c": "json-c",
    "libxml2": "libxml2",
    "libpcre": "pcre",
    "libexpat": "expat",
    "libdbus": "dbus",
    "libreadline": "readline",
    "libncurses": "ncurses",
    # Networking
    "libavahi-client": "avahi",
    "libavahi-common": "avahi",
    "libnl": "libnl",
    "libnl-3": "libnl",
    "libmosquitto": "mosquitto",
    # OpenWrt
    "libubus": "ubus",
    "libubox": "libubox",
    "libuci": "uci",
    "libiwinfo": "iwinfo",
    # Firewall / netfilter
    "libiptc": "iptables",
    "libnfnetlink": "netfilter",
    # System libraries (C runtime)
    "libpthread": "glibc",
    "libdl": "glibc",
    "librt": "glibc",
    "libm": "glibc",
    "libc": "glibc",
    "libgcc_s": "gcc",
    "libstdc++": "gcc",
}

# Firmware OS fingerprinting markers (additional to /etc/os-release)
FIRMWARE_MARKERS: dict[str, list[str]] = {
    "dd-wrt": ["/etc/dd-wrt_version"],
    "buildroot": ["/etc/buildroot_version", "/etc/br-version"],
    "yocto": ["/etc/version", "/etc/build"],
    # Android build.prop is handled by the android strategy which correctly
    # extracts ro.build.version.release (not a raw version regex)
}

# Known services/daemons with risk classification for firmware security
# CRITICAL = should never be in production (plaintext, no auth)
# HIGH = common attack surface requiring review
KNOWN_SERVICE_RISKS: dict[str, str] = {
    # CRITICAL — plaintext protocols with no authentication
    "telnetd": "critical",
    "utelnetd": "critical",
    "rlogind": "critical",
    "rshd": "critical",
    "rexecd": "critical",
    "tftpd": "critical",
    # HIGH — common attack surface
    "ftpd": "high",
    "vsftpd": "high",
    "proftpd": "high",
    "httpd": "high",
    "uhttpd": "high",
    "lighttpd": "high",
    "goahead": "high",
    "miniupnpd": "high",
    "snmpd": "high",
    "smbd": "high",
    "cwmpd": "high",
    "mini_httpd": "high",
    "boa": "high",
    "mongoose": "high",
    # MEDIUM — expected but should be hardened
    "sshd": "medium",
    "dropbear": "medium",
    "dnsmasq": "medium",
    "hostapd": "medium",
    "openvpn": "medium",
    "mosquitto": "medium",
    "rssh": "medium",  # Restricted shell — CVE-2019-3463 command injection
    "stunnel": "medium",  # TLS wrapper — attack surface
    "socat": "medium",  # Socket relay — attack surface
    "ncat": "medium",  # Nmap netcat — attack surface
    "xinetd": "medium",  # Super-server — attack surface
    # HIGH — legacy unencrypted protocols
    "rsh": "high",  # Remote shell — cleartext
    "rexec": "high",  # Remote exec — cleartext
    "inetd": "high",  # Legacy super-server
    # LOW — generally safe
    "ntpd": "low",
    "crond": "low",
    "syslogd": "low",
    "avahi-daemon": "low",
}


@dataclass
class IdentifiedComponent:
    """A software component identified in the firmware."""
    name: str
    version: str | None
    type: str  # 'application', 'library', 'operating-system'
    cpe: str | None = None
    purl: str | None = None
    supplier: str | None = None
    detection_source: str = ""
    detection_confidence: str = "medium"
    file_paths: list[str] = field(default_factory=list)
    metadata: dict = field(default_factory=dict)
    source_partition: str | None = None
