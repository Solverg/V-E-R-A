"""Network Radar collection and public-IP lookup."""
from __future__ import annotations
import ipaddress
import json
import socket
import subprocess
import time
import urllib.error
import urllib.request
from typing import Any
import psutil

def classify_address(address: str) -> str:
    value = str(address or "").strip()
    if not value: return "empty"
    try: ip = ipaddress.ip_address(value)
    except ValueError: return "public"
    if ip.is_loopback: return "loopback"
    if ip.is_private: return "private"
    if ip.is_link_local: return "link-local"
    if ip.is_multicast: return "multicast"
    return "public"

def calculate_risk(name: str, path: str, address_type: str, status: str) -> str:
    if address_type != "public" or status == psutil.CONN_TIME_WAIT: return "low"
    unknown = not name or name.strip().lower() in {"unknown", "без pid", "процесс завершён"}
    location = (path or "").lower()
    if unknown or "\\appdata\\" in location or "\\temp\\" in location: return "attention"
    return "medium" if status == psutil.CONN_ESTABLISHED else "low"

def _address(value: Any) -> tuple[str, int | None]:
    if not value: return "", None
    ip, port = getattr(value, "ip", None), getattr(value, "port", None)
    if ip is None:
        try: ip, port = value[0], value[1]
        except (TypeError, IndexError): return str(value), None
    try: return str(ip or ""), int(port) if port is not None else None
    except (TypeError, ValueError): return str(ip or ""), None

def _process(pid: int | None, status: str) -> tuple[str, str]:
    if not pid: return ("закрыто (TIME_WAIT)", "") if status == psutil.CONN_TIME_WAIT else ("без PID", "")
    try: proc = psutil.Process(pid)
    except psutil.NoSuchProcess: return "процесс завершён", ""
    except psutil.AccessDenied: return f"PID {pid}", ""
    try: name = proc.name() or f"PID {pid}"
    except (psutil.NoSuchProcess, psutil.AccessDenied): name = f"PID {pid}"
    try: path = proc.exe() or ""
    except (psutil.NoSuchProcess, psutil.AccessDenied): path = ""
    return name, path

def _connection_row(pid: int | None, local: str, local_port: int | None, remote: str, remote_port: int | None, status: str, family: str, process_cache: dict[int, tuple[str, str]] | None = None) -> dict[str, Any]:
    numeric_pid = int(pid or 0)
    # A browser or service commonly owns dozens of sockets.  Resolving its
    # executable for every socket repeats expensive Windows process queries.
    # Keep the cache local to a single scan: it cannot make stale process data
    # survive into a later refresh, yet avoids that duplicated work.
    cache_key = numeric_pid
    if process_cache is not None and cache_key in process_cache:
        name, path = process_cache[cache_key]
    else:
        name, path = _process(numeric_pid, status)
        if process_cache is not None:
            process_cache[cache_key] = (name, path)
    address_type = classify_address(remote)
    return {"pid":numeric_pid,"process_name":name,"process_path":path,"local_address":local,"local_port":local_port,"remote_address":remote,"remote_port":remote_port,"status":status,"family":family,"address_type":address_type,"risk":calculate_risk(name,path,address_type,status)}

def _netstat_address(value: str) -> tuple[str, int | None]:
    value = value.strip()
    if not value or value == "*:*": return "", None
    if value.startswith("[") and "]:" in value:
        host, port = value[1:].rsplit("]:", 1)
    elif ":" in value:
        host, port = value.rsplit(":", 1)
    else: return value, None
    if host in {"*", "0.0.0.0"} and port == "0": return "", None
    try: return host, int(port)
    except ValueError: return host, None

def _list_connections_netstat() -> list[dict[str, Any]]:
    """Fallback for Windows hosts where psutil cannot inspect all sockets."""
    try:
        result = subprocess.run(["netstat", "-ano"], capture_output=True, text=True, encoding="utf-8", errors="replace", check=False, timeout=5)
    except (OSError, subprocess.SubprocessError): return []
    rows=[]
    process_cache: dict[int, tuple[str, str]] = {}
    for line in result.stdout.splitlines():
        parts=line.split()
        if len(parts) < 4 or parts[0].upper() not in {"TCP", "UDP"}: continue
        protocol=parts[0].upper(); local,local_port=_netstat_address(parts[1]); remote,remote_port=_netstat_address(parts[2])
        if protocol == "TCP":
            if len(parts) < 5: continue
            status=parts[3].upper().replace("LISTENING", "LISTEN")
            try: pid=int(parts[4])
            except ValueError: continue
        else:
            status="NONE"
            try: pid=int(parts[3])
            except ValueError: continue
        family="IPv6" if ":" in local or ":" in remote else "IPv4"
        rows.append(_connection_row(pid,local,local_port,remote,remote_port,status,family,process_cache))
    return rows

def list_connections() -> list[dict[str, Any]]:
    rows=[]
    process_cache: dict[int, tuple[str, str]] = {}
    try: connections=psutil.net_connections(kind="inet")
    except psutil.AccessDenied: rows=_list_connections_netstat(); connections=[]
    for conn in connections:
        status=str(conn.status or ""); pid=int(conn.pid or 0)
        local,local_port=_address(conn.laddr); remote,remote_port=_address(conn.raddr)
        rows.append(_connection_row(pid,local,local_port,remote,remote_port,status,"IPv4" if conn.family==socket.AF_INET else "IPv6" if conn.family==socket.AF_INET6 else str(conn.family),process_cache))
    order={"attention":0,"medium":1,"low":2}
    return sorted(rows,key=lambda x:(order.get(x["risk"],3),x["process_name"].lower(),x["pid"],x["remote_address"]))

def _fetch(url: str, timeout: float=2.0) -> str:
    req=urllib.request.Request(url, headers={"User-Agent":"V.E.R.A./0.2"})
    with urllib.request.urlopen(req, timeout=timeout) as response: return response.read(65536).decode("utf-8", "replace")

def _ip_details(ip: str, **values: Any) -> dict[str, Any]:
    """Return a consistently shaped response only for a valid public address."""
    try: parsed = ipaddress.ip_address(str(ip).strip())
    except ValueError: return {}
    if parsed.is_unspecified or parsed.is_loopback or parsed.is_private or parsed.is_link_local: return {}
    return {"ip":str(parsed),"country_code":"","country_name":"","city":"","asn":"","provider":"",**values}

def public_ip() -> dict[str, Any]:
    # This endpoint is refreshed in the UI.  A disconnected network must not
    # leave successive sidecar requests accumulating for tens of seconds.
    deadline = time.monotonic() + 6.0
    errors=[]
    def fetch_with_budget(url: str) -> str:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise TimeoutError("Public IP lookup timed out")
        return _fetch(url, timeout=min(2.0, remaining))
    for url, parser in (("https://ipapi.co/json/",lambda d:_ip_details(d.get("ip", ""),country_code=d.get("country_code") or "",country_name=d.get("country_name") or "",city=d.get("city") or "",asn=d.get("asn") or "",provider=d.get("org") or "")),("https://ipwho.is/",lambda d:_ip_details(d.get("ip", ""),country_code=d.get("country_code") or "",country_name=d.get("country") or "",city=d.get("city") or "",asn=(d.get("connection") or {}).get("asn") or "",provider=(d.get("connection") or {}).get("isp") or (d.get("connection") or {}).get("org") or "")),("https://ipinfo.io/json",lambda d:_ip_details(d.get("ip", ""),country_code=d.get("country") or "",country_name=d.get("region") or "",city=d.get("city") or "",provider=d.get("org") or "")),("https://api.ipify.org?format=json",lambda d:_ip_details(d.get("ip", "")))):
        try:
            result=parser(json.loads(fetch_with_budget(url)))
            if result.get("ip"): return result
        except (OSError, ValueError, urllib.error.URLError, TimeoutError) as exc: errors.append(type(exc).__name__)
    for url in ("https://api.ipify.org", "https://api64.ipify.org", "https://icanhazip.com", "https://checkip.amazonaws.com", "https://ifconfig.me/ip"):
        try:
            ip=fetch_with_budget(url).strip()
            result = _ip_details(ip)
            if result: return result
        except (OSError, ValueError, urllib.error.URLError, TimeoutError): pass
    return {"ip":"","country_code":"","country_name":"","city":"","asn":"","provider":"","error":"Не удалось определить внешний IP. Проверьте подключение к сети."}
