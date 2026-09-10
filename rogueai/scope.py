import ipaddress
import re
import urllib.parse

LAB_PREFIX = "lab://"


def parse_target(target):
    t = str(target or "").strip()
    if not t:
        return ("invalid", None, None)
    low = t.lower()
    if low.startswith(LAB_PREFIX):
        return ("lab", low[len(LAB_PREFIX):].rstrip("/"), None)
    if "://" in low:
        u = urllib.parse.urlparse(low)
        if u.scheme == "lab":
            return ("lab", (u.netloc or "").lower(), None)
        return ("host", (u.hostname or "").lower(), u.port)
    if low.startswith("["):
        m = re.match(r"\[([^\]]+)\](?::(\d+))?", low)
        if m:
            return ("host", m.group(1).lower(), int(m.group(2)) if m.group(2) else None)
        return ("invalid", None, None)
    m = re.match(r"([^:]+)(?::(\d+))?$", low)
    if m:
        return ("host", m.group(1).lower(), int(m.group(2)) if m.group(2) else None)
    return ("invalid", None, None)


def is_loopback(host):
    h = (host or "").strip().lower().rstrip(".")
    if h == "localhost":
        return True
    try:
        return ipaddress.ip_address(h).is_loopback
    except ValueError:
        return False


def safe(target):
    kind, value, port = parse_target(target)
    if kind == "lab":
        return bool(value)
    if kind == "host":
        return is_loopback(value)
    return False


def describe(target):
    kind, value, port = parse_target(target)
    if kind == "lab":
        return f"lab fixture: {value}"
    if kind == "host":
        suffix = f":{port}" if port else ""
        label = "loopback" if is_loopback(value) else "external"
        return f"{value}{suffix} ({label})"
    return "invalid target"