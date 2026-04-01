"""SBOM service — identifies software components from unpacked firmware.

Walks the extracted filesystem, parses package databases, scans libraries
and binaries for version information, and returns a deduplicated list of
identified components with CPE and PURL identifiers.
"""

import os
import re
from dataclasses import dataclass, field

from elftools.elf.elffile import ELFFile

from app.utils.sandbox import safe_walk, validate_path

MAX_BINARIES_SCAN = 200
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
    # TR-069/CWMP
    "cwmpd": ("cwmp", "cwmpd"),
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
    # Android build.prop is handled by _scan_android_components() which
    # correctly extracts ro.build.version.release (not a raw version regex)
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


class SbomService:
    """Identifies software components from an unpacked firmware filesystem."""

    def __init__(self, extracted_root: str):
        self.extracted_root = os.path.realpath(extracted_root)
        self._components: dict[tuple[str, str | None], IdentifiedComponent] = {}

    def _validate(self, path: str) -> str:
        return validate_path(self.extracted_root, path)

    def _abs_path(self, rel_path: str) -> str:
        return os.path.join(self.extracted_root, rel_path.lstrip("/"))

    def generate_sbom(self) -> list[dict]:
        """Run all identification strategies and return component list.

        Call from a thread executor (sync, CPU-bound).
        Returns list of dicts ready for DB insertion.
        """
        # Syft first (broad ecosystem coverage, medium confidence).
        # Custom strategies run after and override Syft for same components.
        self._run_syft_scan()

        self._scan_package_managers()
        self._scan_python_packages()
        self._scan_kernel_version()
        self._scan_firmware_markers()
        self._scan_busybox()
        self._scan_c_library()
        self._scan_gcc_version()
        self._scan_library_sonames()
        self._scan_binary_version_strings()
        self._scan_android_components()
        self._annotate_service_risks()

        results = []
        for comp in self._components.values():
            results.append({
                "name": comp.name,
                "version": comp.version,
                "type": comp.type,
                "cpe": comp.cpe,
                "purl": comp.purl,
                "supplier": comp.supplier,
                "detection_source": comp.detection_source,
                "detection_confidence": comp.detection_confidence,
                "file_paths": comp.file_paths or None,
                "metadata": comp.metadata,
            })

        return results

    @staticmethod
    def _normalize_name(name: str) -> str:
        """Normalize package name for dedup (underscores → hyphens, lowercase)."""
        return name.lower().replace("_", "-")

    @staticmethod
    def _normalize_version(version: str | None) -> str | None:
        """Treat '0.0.0' and 'UNKNOWN' as None for merge purposes."""
        if version in (None, "", "0.0.0", "UNKNOWN"):
            return None
        return version

    def _add_component(self, comp: IdentifiedComponent) -> None:
        """Add or merge a component, preferring higher-confidence detections."""
        key = (self._normalize_name(comp.name), self._normalize_version(comp.version))
        existing = self._components.get(key)

        if existing is None:
            self._components[key] = comp
            return

        confidence_rank = {"high": 3, "medium": 2, "low": 1}
        existing_rank = confidence_rank.get(existing.detection_confidence, 0)
        new_rank = confidence_rank.get(comp.detection_confidence, 0)

        # Merge file paths
        merged_paths = list(set(existing.file_paths + comp.file_paths))

        if new_rank > existing_rank:
            # Replace with higher-confidence data, keep merged paths
            comp.file_paths = merged_paths
            self._components[key] = comp
        else:
            existing.file_paths = merged_paths

    @staticmethod
    def _build_cpe(vendor: str, product: str, version: str | None) -> str | None:
        if not version:
            return None
        # Sanitize version for CPE
        ver = version.strip()
        return f"cpe:2.3:a:{vendor}:{product}:{ver}:*:*:*:*:*:*:*"

    @staticmethod
    def _build_purl(name: str, version: str | None, pkg_type: str = "generic") -> str | None:
        if not version:
            return None
        try:
            from packageurl import PackageURL
            purl = PackageURL(type=pkg_type, name=name, version=version)
            return str(purl)
        except Exception:
            # Fallback: construct manually
            return f"pkg:{pkg_type}/{name}@{version}"

    # ------------------------------------------------------------------
    # Strategy 0: Syft directory scan (broad ecosystem coverage)
    # ------------------------------------------------------------------

    # Map Syft package types to Wairz component types
    _SYFT_TYPE_MAP = {
        "deb": "application",
        "rpm": "application",
        "apk": "application",
        "python": "library",
        "go-module": "library",
        "java-archive": "library",
        "npm": "library",
        "gem": "library",
        "rust-crate": "library",
        "php-composer": "library",
        "lua-rock": "library",
        "binary": "application",
        "linux-kernel": "operating-system",
    }

    def _run_syft_scan(self) -> None:
        """Run Syft directory scan and pre-seed components.

        Syft detects packages across 30+ ecosystems (dpkg, Python, Go, Java,
        Node, Rust, Ruby, etc.). Results are added with medium confidence so
        that Wairz's custom firmware-specific strategies can override them
        for components they detect with higher confidence.
        """
        import json
        import subprocess
        from shutil import which

        from app.config import get_settings
        settings = get_settings()

        if not settings.syft_enabled or not which("syft"):
            return

        # Scan the primary extracted root
        scan_dirs = [self.extracted_root]

        # For Android multi-partition extractions, also scan sibling partitions
        # (vendor, product, etc.) that aren't under the system root
        parent = os.path.dirname(self.extracted_root)
        if os.path.basename(parent) == "rootfs":
            for sibling in os.listdir(parent):
                sibling_path = os.path.join(parent, sibling)
                if sibling_path != self.extracted_root and os.path.isdir(sibling_path):
                    scan_dirs.append(sibling_path)

        cdx_components: list[dict] = []
        for scan_dir in scan_dirs:
            try:
                proc = subprocess.run(
                    ["syft", f"dir:{scan_dir}", "-o", "cyclonedx-json", "-q"],
                    capture_output=True,
                    timeout=settings.syft_timeout,
                    text=True,
                )
                if proc.returncode != 0:
                    continue
                cdx = json.loads(proc.stdout)
                cdx_components.extend(cdx.get("components", []))
            except (subprocess.TimeoutExpired, json.JSONDecodeError, Exception):
                continue

        for cdx_comp in cdx_components:
            # Skip file-hash entries (not real packages)
            if cdx_comp.get("type") == "file":
                continue

            name = cdx_comp.get("name", "").strip()
            version = cdx_comp.get("version", "").strip() or None
            if not name:
                continue

            # Skip noise: Windows installer stubs, unknown entries
            if name.startswith("wininst-") or name == "unknown":
                continue

            # Extract Syft metadata from properties array
            props = {p["name"]: p["value"] for p in cdx_comp.get("properties", []) if "name" in p and "value" in p}
            syft_type = props.get("syft:package:type", "")
            cataloger = props.get("syft:package:foundBy", "")
            file_path = props.get("syft:location:0:path", "")

            comp_type = self._SYFT_TYPE_MAP.get(syft_type, "library")

            comp = IdentifiedComponent(
                name=name,
                version=version,
                type=comp_type,
                cpe=cdx_comp.get("cpe"),
                purl=cdx_comp.get("purl"),
                supplier=None,
                detection_source="syft",
                detection_confidence="medium",
                file_paths=[file_path] if file_path else [],
                metadata={"syft_cataloger": cataloger, "syft_type": syft_type},
            )
            self._add_component(comp)

    # ------------------------------------------------------------------
    # Strategy 1: Package manager databases
    # ------------------------------------------------------------------

    def _scan_package_managers(self) -> None:
        """Parse opkg and dpkg status databases."""
        opkg_paths = [
            "/usr/lib/opkg/status",
            "/var/lib/opkg/status",
            "/usr/lib/opkg/info",
        ]
        for rel_path in opkg_paths:
            abs_path = self._abs_path(rel_path)
            if os.path.isfile(abs_path):
                self._parse_opkg_status(abs_path)

        dpkg_path = self._abs_path("/var/lib/dpkg/status")
        if os.path.isfile(dpkg_path):
            self._parse_dpkg_status(dpkg_path)

    def _parse_opkg_status(self, abs_path: str) -> None:
        """Parse an opkg status file (key-value blocks separated by blank lines)."""
        try:
            with open(abs_path, "r", errors="replace") as f:
                content = f.read()
        except OSError:
            return

        blocks = content.split("\n\n")
        for block in blocks:
            if not block.strip():
                continue
            fields = self._parse_control_block(block)
            name = fields.get("package", "").strip()
            version = fields.get("version", "").strip() or None
            if not name:
                continue

            vendor_product = CPE_VENDOR_MAP.get(name.lower())
            cpe = None
            if vendor_product:
                cpe = self._build_cpe(vendor_product[0], vendor_product[1], version)

            comp = IdentifiedComponent(
                name=name,
                version=version,
                type="application",
                cpe=cpe,
                purl=self._build_purl(name, version, "opkg"),
                supplier=vendor_product[0] if vendor_product else None,
                detection_source="package_manager",
                detection_confidence="high",
                file_paths=[],
                metadata={
                    "arch": fields.get("architecture", ""),
                    "description": fields.get("description", ""),
                    "source": "opkg",
                },
            )
            self._add_component(comp)

    def _parse_dpkg_status(self, abs_path: str) -> None:
        """Parse a dpkg status file."""
        try:
            with open(abs_path, "r", errors="replace") as f:
                content = f.read()
        except OSError:
            return

        blocks = content.split("\n\n")
        for block in blocks:
            if not block.strip():
                continue
            fields = self._parse_control_block(block)
            name = fields.get("package", "").strip()
            version = fields.get("version", "").strip() or None
            status = fields.get("status", "")
            if not name:
                continue
            # Only include installed packages
            if "installed" not in status.lower():
                continue

            vendor_product = CPE_VENDOR_MAP.get(name.lower())
            cpe = None
            if vendor_product:
                cpe = self._build_cpe(vendor_product[0], vendor_product[1], version)

            comp = IdentifiedComponent(
                name=name,
                version=version,
                type="application",
                cpe=cpe,
                purl=self._build_purl(name, version, "deb"),
                supplier=vendor_product[0] if vendor_product else None,
                detection_source="package_manager",
                detection_confidence="high",
                file_paths=[],
                metadata={
                    "arch": fields.get("architecture", ""),
                    "description": fields.get("description", ""),
                    "source": "dpkg",
                },
            )
            self._add_component(comp)

    @staticmethod
    def _parse_control_block(block: str) -> dict[str, str]:
        """Parse a Debian-style control file block into a dict."""
        fields: dict[str, str] = {}
        current_key = ""
        current_val = ""
        for line in block.splitlines():
            if line.startswith((" ", "\t")):
                # Continuation line
                current_val += "\n" + line.strip()
            elif ":" in line:
                # Save previous field
                if current_key:
                    fields[current_key.lower()] = current_val
                key, _, val = line.partition(":")
                current_key = key.strip()
                current_val = val.strip()
        if current_key:
            fields[current_key.lower()] = current_val
        return fields

    # ------------------------------------------------------------------
    # Strategy 1b: Python packages (.dist-info / .egg-info)
    # ------------------------------------------------------------------

    def _scan_python_packages(self) -> None:
        """Detect Python packages from .dist-info and .egg-info directories."""
        # Common Python site-packages locations in firmware
        site_paths = [
            "usr/lib/python*/site-packages",
            "usr/lib/python*/dist-packages",
            "usr/local/lib/python*/site-packages",
        ]
        import glob as _glob

        for pattern in site_paths:
            full_pattern = os.path.join(self.extracted_root, pattern)
            for site_dir in _glob.glob(full_pattern):
                if not os.path.isdir(site_dir):
                    continue
                try:
                    entries = os.listdir(site_dir)
                except OSError:
                    continue
                for entry in entries:
                    name = None
                    version = None
                    rel_path = os.path.relpath(
                        os.path.join(site_dir, entry), self.extracted_root
                    )

                    if entry.endswith(".dist-info"):
                        # PEP 376: name-version.dist-info
                        meta_file = os.path.join(site_dir, entry, "METADATA")
                        if not os.path.isfile(meta_file):
                            meta_file = os.path.join(site_dir, entry, "PKG-INFO")
                        name, version = self._parse_python_metadata(meta_file)
                        if not name:
                            # Fallback: parse directory name
                            parts = entry[:-len(".dist-info")].rsplit("-", 1)
                            name = parts[0].lower().replace("_", "-")
                            version = parts[1] if len(parts) > 1 else None

                    elif entry.endswith(".egg-info"):
                        # setuptools: name-version.egg-info
                        meta_path = os.path.join(site_dir, entry)
                        if os.path.isdir(meta_path):
                            meta_file = os.path.join(meta_path, "PKG-INFO")
                        else:
                            meta_file = meta_path  # single-file .egg-info
                        name, version = self._parse_python_metadata(meta_file)
                        if not name:
                            parts = entry[:-len(".egg-info")].rsplit("-", 1)
                            name = parts[0].lower().replace("_", "-")
                            version = parts[1] if len(parts) > 1 else None

                    if not name or name == "unknown":
                        continue

                    # Skip placeholder entries
                    if version == "0.0.0":
                        version = None

                    comp = IdentifiedComponent(
                        name=name,
                        version=version,
                        type="library",
                        cpe=None,  # Python packages rarely have CPEs
                        purl=self._build_purl(name, version, "pypi"),
                        supplier=None,
                        detection_source="python_package",
                        detection_confidence="high",
                        file_paths=[f"/{rel_path}"],
                        metadata={"source": "python", "ecosystem": "pypi"},
                    )
                    self._add_component(comp)

    @staticmethod
    def _parse_python_metadata(meta_file: str) -> tuple[str | None, str | None]:
        """Parse Name and Version from a Python METADATA or PKG-INFO file."""
        if not os.path.isfile(meta_file):
            return None, None
        name = None
        version = None
        try:
            with open(meta_file, "r", errors="replace") as f:
                for line in f:
                    if line.startswith("Name:"):
                        name = line[5:].strip().lower()
                    elif line.startswith("Version:"):
                        version = line[8:].strip()
                    elif line.startswith(" ") or line.startswith("\t"):
                        continue
                    elif name and version:
                        break  # Got both, stop reading
        except OSError:
            pass
        return name, version

    # ------------------------------------------------------------------
    # Strategy 1c: Android components (APKs, build.prop, init services)
    # ------------------------------------------------------------------

    def _scan_android_components(self) -> None:
        """Detect Android-specific components: APKs, system properties, init services."""
        # Check if this is an Android filesystem
        build_prop = None
        for bp_path in ("system/build.prop", "build.prop", "vendor/build.prop"):
            abs_bp = os.path.join(self.extracted_root, bp_path)
            if os.path.isfile(abs_bp):
                build_prop = abs_bp
                break

        if build_prop is None:
            return  # Not Android

        # 1. Parse build.prop for system metadata
        self._parse_build_prop(build_prop)

        # 2. Scan APKs in standard Android app directories
        for app_dir in ("system/app", "system/priv-app", "product/app",
                        "product/priv-app", "vendor/app"):
            abs_dir = os.path.join(self.extracted_root, app_dir)
            if not os.path.isdir(abs_dir):
                continue
            try:
                for app_name in os.listdir(abs_dir):
                    app_path = os.path.join(abs_dir, app_name)
                    if not os.path.isdir(app_path):
                        continue
                    # Each app is a directory containing the APK
                    priv = "priv-app" in app_dir
                    comp = IdentifiedComponent(
                        name=app_name,
                        version=None,
                        type="application",
                        cpe=None,
                        purl=None,
                        supplier=None,
                        detection_source="android_apk",
                        detection_confidence="high",
                        file_paths=[f"/{app_dir}/{app_name}"],
                        metadata={
                            "android_app_type": "privileged" if priv else "system",
                            "source": "android",
                        },
                    )
                    self._add_component(comp)
            except OSError:
                continue

        # 3. Parse init services from .rc files
        for init_dir in ("system/etc/init", "vendor/etc/init", "product/etc/init"):
            abs_dir = os.path.join(self.extracted_root, init_dir)
            if not os.path.isdir(abs_dir):
                continue
            try:
                for rc_name in os.listdir(abs_dir):
                    if not rc_name.endswith(".rc"):
                        continue
                    rc_path = os.path.join(abs_dir, rc_name)
                    self._parse_android_init_rc(rc_path, init_dir)
            except OSError:
                continue

        # 4. Scan kernel modules in vendor
        for mod_dir in ("vendor/lib/modules", "vendor/lib64/modules",
                        "system/lib/modules"):
            abs_dir = os.path.join(self.extracted_root, mod_dir)
            if not os.path.isdir(abs_dir):
                continue
            try:
                for mod_name in os.listdir(abs_dir):
                    if not mod_name.endswith(".ko"):
                        continue
                    comp = IdentifiedComponent(
                        name=mod_name.replace(".ko", ""),
                        version=None,
                        type="library",
                        cpe=None,
                        purl=None,
                        supplier=None,
                        detection_source="android_kernel_module",
                        detection_confidence="medium",
                        file_paths=[f"/{mod_dir}/{mod_name}"],
                        metadata={"source": "android", "type": "kernel_module"},
                    )
                    self._add_component(comp)
            except OSError:
                continue

    def _parse_build_prop(self, abs_path: str) -> None:
        """Parse Android build.prop for version info and platform details."""
        props: dict[str, str] = {}
        try:
            with open(abs_path, "r", errors="replace") as f:
                for line in f:
                    line = line.strip()
                    if line.startswith("#") or "=" not in line:
                        continue
                    key, _, value = line.partition("=")
                    props[key.strip()] = value.strip()
        except OSError:
            return

        # Android OS version
        android_version = props.get("ro.build.version.release") or props.get("ro.system.build.version.release")
        security_patch = props.get("ro.build.version.security_patch")
        build_id = props.get("ro.build.display.id") or props.get("ro.system.build.id")
        platform = props.get("ro.board.platform", "")
        model = props.get("ro.product.model") or props.get("ro.product.system.model", "")

        if android_version:
            comp = IdentifiedComponent(
                name="android",
                version=android_version,
                type="operating-system",
                cpe=f"cpe:2.3:o:google:android:{android_version}:*:*:*:*:*:*:*",
                purl=None,
                supplier="google",
                detection_source="android_build_prop",
                detection_confidence="high",
                file_paths=[abs_path.replace(self.extracted_root, "")],
                metadata={
                    "security_patch": security_patch,
                    "build_id": build_id,
                    "platform": platform,
                    "model": model,
                    "source": "android",
                },
            )
            self._add_component(comp)

        # SELinux status
        selinux_dir = os.path.join(self.extracted_root, "system", "etc", "selinux")
        if os.path.isdir(selinux_dir):
            comp = IdentifiedComponent(
                name="android-selinux-policy",
                version=None,
                type="library",
                cpe=None,
                purl=None,
                supplier="google",
                detection_source="android_selinux",
                detection_confidence="high",
                file_paths=["/system/etc/selinux"],
                metadata={"source": "android", "type": "security_policy"},
            )
            self._add_component(comp)

    def _parse_android_init_rc(self, abs_path: str, rel_dir: str) -> None:
        """Parse an Android .rc init file for service declarations."""
        try:
            with open(abs_path, "r", errors="replace") as f:
                for line in f:
                    line = line.strip()
                    if line.startswith("service "):
                        parts = line.split()
                        if len(parts) >= 3:
                            service_name = parts[1]
                            binary_path = parts[2]
                            rc_name = os.path.basename(abs_path)
                            comp = IdentifiedComponent(
                                name=f"init-{service_name}",
                                version=None,
                                type="application",
                                cpe=None,
                                purl=None,
                                supplier=None,
                                detection_source="android_init_service",
                                detection_confidence="medium",
                                file_paths=[f"/{rel_dir}/{rc_name}"],
                                metadata={
                                    "binary": binary_path,
                                    "source": "android",
                                    "type": "init_service",
                                },
                            )
                            self._add_component(comp)
        except OSError:
            pass

    # ------------------------------------------------------------------
    # Strategy 2: Kernel version
    # ------------------------------------------------------------------

    def _scan_kernel_version(self) -> None:
        """Detect Linux kernel version from modules directory and release files."""
        # Check /lib/modules/*/
        modules_dir = self._abs_path("/lib/modules")
        if os.path.isdir(modules_dir):
            try:
                for entry in os.listdir(modules_dir):
                    entry_path = os.path.join(modules_dir, entry)
                    if os.path.isdir(entry_path) and re.match(r"\d+\.\d+", entry):
                        # Extract base kernel version (strip local version suffix)
                        match = re.match(r"(\d+\.\d+\.\d+)", entry)
                        version = match.group(1) if match else entry
                        comp = IdentifiedComponent(
                            name="linux-kernel",
                            version=version,
                            type="operating-system",
                            cpe=f"cpe:2.3:o:linux:linux_kernel:{version}:*:*:*:*:*:*:*",
                            purl=self._build_purl("linux", version),
                            supplier="linux",
                            detection_source="kernel_modules",
                            detection_confidence="high",
                            file_paths=[f"/lib/modules/{entry}"],
                            metadata={"full_version": entry},
                        )
                        self._add_component(comp)
                        break  # Usually only one kernel version
            except OSError:
                pass

        # Check /etc/os-release, /etc/openwrt_release for distro info
        for rel_file in ["/etc/os-release", "/etc/openwrt_release"]:
            abs_path = self._abs_path(rel_file)
            if os.path.isfile(abs_path):
                self._parse_os_release(abs_path, rel_file)

    def _parse_os_release(self, abs_path: str, rel_path: str) -> None:
        """Parse os-release or openwrt_release for distro identification."""
        try:
            with open(abs_path, "r", errors="replace") as f:
                content = f.read(4096)
        except OSError:
            return

        fields: dict[str, str] = {}
        for line in content.splitlines():
            line = line.strip()
            if "=" in line and not line.startswith("#"):
                key, _, val = line.partition("=")
                fields[key.strip()] = val.strip().strip("'\"")

        distro_id = fields.get("ID", fields.get("DISTRIB_ID", "")).lower()
        distro_version = fields.get("VERSION_ID", fields.get("DISTRIB_RELEASE", ""))
        distro_name = fields.get("NAME", fields.get("DISTRIB_DESCRIPTION", distro_id))

        if distro_id and distro_version:
            comp = IdentifiedComponent(
                name=distro_id,
                version=distro_version,
                type="operating-system",
                cpe=self._build_cpe(distro_id, distro_id, distro_version),
                purl=self._build_purl(distro_id, distro_version),
                supplier=distro_id,
                detection_source="config_file",
                detection_confidence="high",
                file_paths=[rel_path],
                metadata={"display_name": distro_name},
            )
            self._add_component(comp)

    # ------------------------------------------------------------------
    # Strategy 2b: Firmware OS fingerprinting via marker files
    # ------------------------------------------------------------------

    def _scan_firmware_markers(self) -> None:
        """Check for firmware distro marker files beyond os-release."""
        for distro_id, marker_paths in FIRMWARE_MARKERS.items():
            for rel_path in marker_paths:
                abs_path = self._abs_path(rel_path)
                if not os.path.isfile(abs_path):
                    continue
                try:
                    with open(abs_path, "r", errors="replace") as f:
                        content = f.read(1024).strip()
                except OSError:
                    continue
                if not content:
                    continue

                # Try to extract a version number from the file content
                version_match = re.search(r"(\d+\.\d+(?:\.\d+)?)", content)
                version = version_match.group(1) if version_match else content[:50]

                comp = IdentifiedComponent(
                    name=distro_id,
                    version=version,
                    type="operating-system",
                    cpe=self._build_cpe(distro_id, distro_id, version),
                    purl=self._build_purl(distro_id, version),
                    supplier=distro_id,
                    detection_source="config_file",
                    detection_confidence="high",
                    file_paths=[rel_path],
                    metadata={"marker_file": rel_path, "raw_content": content[:200]},
                )
                self._add_component(comp)
                break  # Only need one marker per distro

    # ------------------------------------------------------------------
    # Dedicated BusyBox detection (critical for embedded Linux)
    # ------------------------------------------------------------------

    def _scan_busybox(self) -> None:
        """Explicitly search for BusyBox, which is present in most embedded
        Linux firmware.  BusyBox installs as a single binary with hundreds
        of symlinks, so the generic binary scanner (which skips symlinks)
        may miss it depending on layout.  We resolve symlinks here and read
        the actual binary to extract the version string."""

        # Common locations where the real busybox binary (or a symlink to
        # it) lives.  We also check /bin/sh since it's almost always a
        # symlink to busybox on embedded systems.
        candidates = [
            "/bin/busybox",
            "/bin/busybox.nosuid",
            "/bin/busybox.suid",
            "/usr/bin/busybox",
            "/sbin/busybox",
            "/bin/sh",
        ]

        checked_realpaths: set[str] = set()

        for candidate in candidates:
            abs_path = self._abs_path(candidate)

            # Resolve symlinks so we read the actual binary
            try:
                real_path = os.path.realpath(abs_path)
            except OSError:
                continue

            # Stay inside the extracted root
            if not real_path.startswith(self.extracted_root):
                continue
            if not os.path.isfile(real_path):
                continue
            # Don't scan the same underlying file twice
            if real_path in checked_realpaths:
                continue
            checked_realpaths.add(real_path)

            # Quick ELF check
            try:
                with open(real_path, "rb") as f:
                    if f.read(4) != b"\x7fELF":
                        continue
            except OSError:
                continue

            # Read and search for BusyBox version string
            try:
                with open(real_path, "rb") as f:
                    data = f.read(MAX_BINARY_READ)
            except OSError:
                continue

            match = re.search(rb"BusyBox v(\d+\.\d+(?:\.\d+)?)", data)
            if match:
                version = match.group(1).decode("ascii", errors="replace")
                rel_path = "/" + os.path.relpath(real_path, self.extracted_root)

                comp = IdentifiedComponent(
                    name="busybox",
                    version=version,
                    type="application",
                    cpe=self._build_cpe("busybox", "busybox", version),
                    purl=self._build_purl("busybox", version),
                    supplier="busybox",
                    detection_source="binary_strings",
                    detection_confidence="high",
                    file_paths=[rel_path],
                    metadata={"detection_note": "dedicated busybox scan"},
                )
                self._add_component(comp)
                return  # Found it, no need to check more candidates

    # ------------------------------------------------------------------
    # Dedicated C library detection
    # ------------------------------------------------------------------

    def _scan_c_library(self) -> None:
        """Detect the C library (glibc, uClibc-ng, musl) and its version.

        Firmware has exactly one C library; we return after the first
        identification.  Reads up to MAX_LIBC_READ because libc binaries
        are large and the version string may be far into the file.
        """
        # Static candidate paths
        candidates: list[str] = [
            "/lib/libc.so.6",
            "/lib/libc.so.0",
        ]

        # Dynamic candidates from /lib directory listing
        lib_abs = self._abs_path("/lib")
        if os.path.isdir(lib_abs):
            try:
                for entry in os.listdir(lib_abs):
                    if entry.startswith(("ld-linux", "ld-musl-", "ld-uClibc")):
                        candidates.append(f"/lib/{entry}")
                    elif entry.startswith("libc.so."):
                        path = f"/lib/{entry}"
                        if path not in candidates:
                            candidates.append(path)
            except OSError:
                pass

        checked_realpaths: set[str] = set()

        for candidate in candidates:
            abs_path = self._abs_path(candidate)
            try:
                real_path = os.path.realpath(abs_path)
            except OSError:
                continue
            if not real_path.startswith(self.extracted_root):
                continue
            if not os.path.isfile(real_path):
                continue
            if real_path in checked_realpaths:
                continue
            checked_realpaths.add(real_path)

            try:
                with open(real_path, "rb") as f:
                    if f.read(4) != b"\x7fELF":
                        continue
                    f.seek(0)
                    data = f.read(MAX_LIBC_READ)
            except OSError:
                continue

            rel_path = "/" + os.path.relpath(real_path, self.extracted_root)

            # --- glibc detection ---
            # String match: "GNU C Library ... version 2.31"
            m = re.search(rb"GNU C Library[^\n]*version (\d+\.\d+(?:\.\d+)?)", data)
            if not m:
                m = re.search(rb"stable release version (\d+\.\d+(?:\.\d+)?)", data)
            if m:
                version = m.group(1).decode("ascii", errors="replace")
                self._add_component(IdentifiedComponent(
                    name="glibc",
                    version=version,
                    type="library",
                    cpe=self._build_cpe("gnu", "glibc", version),
                    purl=self._build_purl("glibc", version),
                    supplier="gnu",
                    detection_source="binary_strings",
                    detection_confidence="high",
                    file_paths=[rel_path],
                    metadata={"detection_note": "dedicated C library scan"},
                ))
                return

            # Fallback: pick highest GLIBC_X.Y symbol version
            glibc_versions = re.findall(rb"GLIBC_(\d+\.\d+(?:\.\d+)?)", data)
            if glibc_versions:
                parsed = []
                for v in set(glibc_versions):
                    try:
                        parts = tuple(int(x) for x in v.decode("ascii").split("."))
                        parsed.append((parts, v.decode("ascii")))
                    except (ValueError, UnicodeDecodeError):
                        continue
                if parsed:
                    parsed.sort(key=lambda x: x[0], reverse=True)
                    version = parsed[0][1]
                    self._add_component(IdentifiedComponent(
                        name="glibc",
                        version=version,
                        type="library",
                        cpe=self._build_cpe("gnu", "glibc", version),
                        purl=self._build_purl("glibc", version),
                        supplier="gnu",
                        detection_source="binary_strings",
                        detection_confidence="medium",
                        file_paths=[rel_path],
                        metadata={
                            "detection_note": "inferred from GLIBC symbol versions",
                        },
                    ))
                    return

            # --- uClibc-ng detection ---
            m = re.search(rb"uClibc(?:-ng)? (\d+\.\d+\.\d+)", data)
            if m:
                version = m.group(1).decode("ascii", errors="replace")
                self._add_component(IdentifiedComponent(
                    name="uclibc-ng",
                    version=version,
                    type="library",
                    cpe=self._build_cpe("uclibc", "uclibc", version),
                    purl=self._build_purl("uclibc-ng", version),
                    supplier="uclibc",
                    detection_source="binary_strings",
                    detection_confidence="high",
                    file_paths=[rel_path],
                    metadata={"detection_note": "dedicated C library scan"},
                ))
                return

            # --- musl detection ---
            m = re.search(rb"musl libc (\d+\.\d+\.\d+)", data)
            if m:
                version = m.group(1).decode("ascii", errors="replace")
                self._add_component(IdentifiedComponent(
                    name="musl",
                    version=version,
                    type="library",
                    cpe=self._build_cpe("musl-libc", "musl", version),
                    purl=self._build_purl("musl", version),
                    supplier="musl-libc",
                    detection_source="binary_strings",
                    detection_confidence="high",
                    file_paths=[rel_path],
                    metadata={"detection_note": "dedicated C library scan"},
                ))
                return

    # ------------------------------------------------------------------
    # Dedicated GCC version detection
    # ------------------------------------------------------------------

    def _scan_gcc_version(self) -> None:
        """Detect the GCC version used to compile the firmware.

        Probes a few common binaries for the ``GCC: (toolchain) X.Y.Z``
        string embedded by the compiler.  Returns after first match
        because the GCC version is consistent across a build.
        """
        probe_paths = [
            "/bin/busybox",
            "/sbin/init",
            "/lib/libc.so.6",
            "/lib/libc.so.0",
            "/usr/sbin/httpd",
            "/usr/bin/curl",
        ]

        checked_realpaths: set[str] = set()

        for probe in probe_paths:
            abs_path = self._abs_path(probe)
            try:
                real_path = os.path.realpath(abs_path)
            except OSError:
                continue
            if not real_path.startswith(self.extracted_root):
                continue
            if not os.path.isfile(real_path):
                continue
            if real_path in checked_realpaths:
                continue
            checked_realpaths.add(real_path)

            try:
                with open(real_path, "rb") as f:
                    if f.read(4) != b"\x7fELF":
                        continue
                    f.seek(0)
                    data = f.read(MAX_BINARY_READ)
            except OSError:
                continue

            m = re.search(rb"GCC: \(([^)]*)\) (\d+\.\d+\.\d+)", data)
            if m:
                toolchain = m.group(1).decode("ascii", errors="replace")
                version = m.group(2).decode("ascii", errors="replace")
                rel_path = "/" + os.path.relpath(real_path, self.extracted_root)

                metadata: dict = {"detection_note": "dedicated GCC scan"}
                if toolchain:
                    metadata["toolchain"] = toolchain

                self._add_component(IdentifiedComponent(
                    name="gcc",
                    version=version,
                    type="application",
                    cpe=self._build_cpe("gnu", "gcc", version),
                    purl=self._build_purl("gcc", version),
                    supplier="gnu",
                    detection_source="binary_strings",
                    detection_confidence="high",
                    file_paths=[rel_path],
                    metadata=metadata,
                ))
                return

    # ------------------------------------------------------------------
    # Strategy 3: Library SONAME parsing
    # ------------------------------------------------------------------

    def _scan_library_sonames(self) -> None:
        """Scan shared library files for version information.

        Uses safe_walk() for recursive scanning so libraries in
        subdirectories (e.g. /lib/ipsec/, /usr/lib/lua/) are found.
        When a library has a useless version (single digit like "6"),
        falls back to reading binary content for a real version string.
        """
        lib_dirs = [
            "/lib", "/usr/lib", "/lib64", "/usr/lib64",
        ]
        seen_libs: set[str] = set()

        for lib_dir in lib_dirs:
            abs_dir = self._abs_path(lib_dir)
            if not os.path.isdir(abs_dir):
                continue

            for dirpath, _dirs, files in safe_walk(abs_dir):
                # Stay inside the extracted root
                if not dirpath.startswith(self.extracted_root):
                    continue

                for entry in files:
                    if ".so" not in entry:
                        continue
                    abs_path = os.path.join(dirpath, entry)
                    if not os.path.isfile(abs_path):
                        continue
                    # Skip symlinks to avoid double-counting
                    if os.path.islink(abs_path):
                        continue

                    dir_rel = "/" + os.path.relpath(dirpath, self.extracted_root)
                    file_rel = f"{dir_rel}/{entry}"

                    lib_info = self._parse_library_file(abs_path, file_rel)
                    if not lib_info or lib_info["name"] in seen_libs:
                        continue

                    version = lib_info["version"]
                    component_name = lib_info["name"]

                    # If the version is useless, try to extract from binary content.
                    # If content extraction also fails, skip — a dedicated scanner
                    # or the binary string scanner will find the real version.
                    if self._is_useless_version(version):
                        content_version = self._extract_version_from_library_content(
                            abs_path, component_name
                        )
                        if content_version:
                            version = content_version
                        else:
                            continue

                    seen_libs.add(component_name)
                    vendor_product = CPE_VENDOR_MAP.get(component_name.lower())
                    cpe = None
                    if vendor_product:
                        cpe = self._build_cpe(vendor_product[0], vendor_product[1], version)

                    comp = IdentifiedComponent(
                        name=component_name,
                        version=version,
                        type="library",
                        cpe=cpe,
                        purl=self._build_purl(component_name, version),
                        supplier=vendor_product[0] if vendor_product else None,
                        detection_source="library_soname",
                        detection_confidence="high",
                        file_paths=[file_rel],
                        metadata={"soname": lib_info.get("soname", "")},
                    )
                    self._add_component(comp)

    @staticmethod
    def _is_useless_version(version: str | None) -> bool:
        """Return True if the version is missing or unlikely to be a real
        software version.

        SONAME versions like "6" (libc.so.6), "0" (libc.so.0), or "200"
        (libnl-3.so.200) are just ABI version numbers, not real
        upstream software versions.  Real versions have at least one dot
        (e.g. "1.2", "2.31", "1.0.2k").
        """
        if not version:
            return True
        # A bare integer (no dots) is almost always a SONAME ABI version
        return bool(re.fullmatch(r"\d+", version))

    def _extract_version_from_library_content(
        self, abs_path: str, component_name: str
    ) -> str | None:
        """Read a library binary and match VERSION_PATTERNS for its component.

        Returns the extracted version string, or None.
        """
        try:
            with open(abs_path, "rb") as f:
                data = f.read(MAX_BINARY_READ)
        except OSError:
            return None

        name_lower = component_name.lower()
        for pattern_name, pattern in VERSION_PATTERNS:
            if pattern_name.lower() != name_lower:
                continue
            m = pattern.search(data)
            if m:
                return m.group(1).decode("ascii", errors="replace")
        return None

    def _parse_library_file(self, abs_path: str, rel_path: str) -> dict | None:
        """Extract component name and version from a shared library file."""
        basename = os.path.basename(abs_path)

        # Try to get SONAME from ELF
        soname = None
        try:
            with open(abs_path, "rb") as f:
                magic = f.read(4)
                if magic != b"\x7fELF":
                    return None
                f.seek(0)
                elf = ELFFile(f)
                for seg in elf.iter_segments():
                    if seg.header.p_type == "PT_DYNAMIC":
                        for tag in seg.iter_tags():
                            if tag.entry.d_tag == "DT_SONAME":
                                soname = tag.soname
                        break
        except Exception:
            return None

        # Parse version from filename: libfoo.so.1.2.3 -> name=libfoo, version=1.2.3
        name, version = self._parse_so_version(soname or basename)
        if not name:
            return None

        # Map library name to component name
        component_name = SONAME_COMPONENT_MAP.get(name, name)

        return {
            "name": component_name,
            "version": version,
            "soname": soname or basename,
        }

    @staticmethod
    def _parse_so_version(filename: str) -> tuple[str | None, str | None]:
        """Parse a .so filename into (name, version).

        Examples:
            libssl.so.1.1 -> (libssl, 1.1)
            libcrypto.so.1.1.1k -> (libcrypto, 1.1.1k)
            libc.so.6 -> (libc, 6)
            libfoo.so -> (libfoo, None)
        """
        # Match libXXX.so.VERSION
        match = re.match(r"^(lib[\w+-]+)\.so\.(.+)$", filename)
        if match:
            name = match.group(1)
            version = match.group(2)
            return name, version

        # Match libXXX.so (no version)
        match = re.match(r"^(lib[\w+-]+)\.so$", filename)
        if match:
            return match.group(1), None

        # Match libXXX-VERSION.so
        match = re.match(r"^(lib[\w+-]+)-(\d[\d.]+\w*)\.so$", filename)
        if match:
            return match.group(1), match.group(2)

        return None, None

    # ------------------------------------------------------------------
    # Strategy 4: Binary version strings
    # ------------------------------------------------------------------

    def _scan_binary_version_strings(self) -> None:
        """Scan ELF binaries in standard paths for version strings."""
        bin_dirs = ["/bin", "/sbin", "/usr/bin", "/usr/sbin"]
        scanned = 0

        for bin_dir in bin_dirs:
            abs_dir = self._abs_path(bin_dir)
            if not os.path.isdir(abs_dir):
                continue
            try:
                entries = os.listdir(abs_dir)
            except OSError:
                continue

            for entry in sorted(entries):
                if scanned >= MAX_BINARIES_SCAN:
                    return

                abs_path = os.path.join(abs_dir, entry)
                if not os.path.isfile(abs_path):
                    continue
                # Skip symlinks
                if os.path.islink(abs_path):
                    continue

                # Quick ELF check
                try:
                    with open(abs_path, "rb") as f:
                        if f.read(4) != b"\x7fELF":
                            continue
                except OSError:
                    continue

                scanned += 1
                self._scan_binary_strings(abs_path, f"{bin_dir}/{entry}")

    def _scan_binary_strings(self, abs_path: str, rel_path: str) -> None:
        """Extract printable strings from a binary and match version patterns."""
        try:
            with open(abs_path, "rb") as f:
                data = f.read(MAX_BINARY_READ)
        except OSError:
            return

        # Extract printable ASCII strings (min length 4)
        strings = self._extract_printable_strings(data, min_length=4)
        combined = b"\n".join(strings)

        for component_name, pattern in VERSION_PATTERNS:
            match = pattern.search(combined)
            if match:
                version = match.group(1).decode("ascii", errors="replace")

                # Skip if we already have this component from a higher-confidence source
                key = (component_name.lower(), version)
                existing = self._components.get(key)
                if existing and existing.detection_confidence == "high":
                    continue

                vendor_product = CPE_VENDOR_MAP.get(component_name.lower())
                cpe = None
                if vendor_product:
                    cpe = self._build_cpe(vendor_product[0], vendor_product[1], version)

                comp = IdentifiedComponent(
                    name=component_name,
                    version=version,
                    type="application",
                    cpe=cpe,
                    purl=self._build_purl(component_name, version),
                    supplier=vendor_product[0] if vendor_product else None,
                    detection_source="binary_strings",
                    detection_confidence="medium",
                    file_paths=[rel_path],
                    metadata={},
                )
                self._add_component(comp)

    @staticmethod
    def _extract_printable_strings(data: bytes, min_length: int = 4) -> list[bytes]:
        """Extract printable ASCII strings from binary data."""
        strings = []
        current = bytearray()
        for byte in data:
            if 0x20 <= byte < 0x7F:
                current.append(byte)
            else:
                if len(current) >= min_length:
                    strings.append(bytes(current))
                current = bytearray()
        if len(current) >= min_length:
            strings.append(bytes(current))
        return strings

    # ------------------------------------------------------------------
    # Post-processing: Annotate service risk levels
    # ------------------------------------------------------------------

    def _annotate_service_risks(self) -> None:
        """Tag identified components with service risk levels.

        Checks binary names in standard daemon paths and annotates
        components that match known services with their risk level.
        """
        # Check for known service binaries in the filesystem
        daemon_dirs = ["/usr/sbin", "/sbin", "/usr/bin", "/bin"]

        for daemon_dir in daemon_dirs:
            abs_dir = self._abs_path(daemon_dir)
            if not os.path.isdir(abs_dir):
                continue
            try:
                entries = os.listdir(abs_dir)
            except OSError:
                continue

            for entry in entries:
                risk = KNOWN_SERVICE_RISKS.get(entry)
                if not risk:
                    continue

                # Find and annotate the matching component
                for comp in self._components.values():
                    if comp.name.lower() == entry or entry in (
                        p.rsplit("/", 1)[-1] for p in comp.file_paths
                    ):
                        comp.metadata["service_risk"] = risk
                        break
                else:
                    # Service binary found but not yet identified as a component —
                    # add it as a low-confidence detection so it shows up in SBOM
                    rel_path = f"{daemon_dir}/{entry}"
                    vendor_product = CPE_VENDOR_MAP.get(entry.lower())

                    comp = IdentifiedComponent(
                        name=entry,
                        version=None,
                        type="application",
                        cpe=None,
                        purl=None,
                        supplier=vendor_product[0] if vendor_product else None,
                        detection_source="binary_strings",
                        detection_confidence="low",
                        file_paths=[rel_path],
                        metadata={"service_risk": risk},
                    )
                    self._add_component(comp)
