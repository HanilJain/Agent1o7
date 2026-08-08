"""Shared constants used across pipeline stages."""

from __future__ import annotations

# Network-facing daemon binary names commonly found in router firmware. These
# are the highest-value targets for Stage 1's ELF shortlist: matches here get
# a strong score boost since they historically carry a disproportionate share
# of router-firmware CVEs (buffer overflows in HTTP/UPnP parsing, auth bypass
# in telnet/SSH daemons, command injection in vendor CGI handlers, etc.).
TARGET_DAEMONS: frozenset[str] = frozenset(
    {
        # HTTP/CGI admin interfaces
        "httpd",
        "lighttpd",
        "boa",
        "goahead",
        "alphapd",
        # UPnP / port-mapping
        "upnpd",
        "miniupnpd",
        "upnp",
        # WiFi / vendor network daemons
        "nas",
        "eapd",
        "hostapd",
        "wpa_supplicant",
        # DNS/DHCP
        "dnsmasq",
        "udhcpd",
        "udhcpc",
        # Remote access
        "telnetd",
        "dropbear",
        "sshd",
        # Misc management/RPC
        "cwmp",
        "tr069",
        "smbd",
        "nmbd",
    }
)

# Substring patterns (lowercased) used as a weaker secondary signal when a
# binary's name doesn't exactly match TARGET_DAEMONS but looks related.
TARGET_DAEMON_SUBSTRINGS: tuple[str, ...] = (
    "http",
    "upnp",
    "wps",
    "wlan",
    "wifi",
    "cgi",
    "cwmp",
    "tr069",
    "dhcp",
    "telnet",
    "ssh",
)

# Directories commonly holding rootfs binaries/libraries, used to bias the
# filesystem walk and skip irrelevant paths (e.g. /proc, /sys placeholders).
ROOTFS_BIN_DIRS: tuple[str, ...] = ("bin", "sbin", "usr/bin", "usr/sbin")
ROOTFS_SKIP_DIRS: frozenset[str] = frozenset({"proc", "sys", "dev"})

# ELF identification.
ELF_MAGIC = b"\x7fELF"
