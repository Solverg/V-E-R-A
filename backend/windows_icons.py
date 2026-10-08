"""Small, dependency-free Windows executable icon reader.

The process snapshot must stay cheap: this module is used only by the
``processes.icons`` batch request for rows that are already visible in the UI.
It deliberately avoids paths on UNC and remote volumes, because asking the
Shell about one of those can block on an unavailable network location.
"""

from __future__ import annotations

import base64
import ctypes
import hashlib
import json
import os
import struct
import time
import zlib
from ctypes import wintypes
from pathlib import Path


ICON_SIZE = 32
MAX_ICON_BATCH = 32
ICON_CACHE_VERSION = 1
ICON_CACHE_TTL_SECONDS = 30 * 24 * 60 * 60
ICON_FAILURE_CACHE_TTL_SECONDS = 24 * 60 * 60


def _png_rgba(width: int, height: int, rgba: bytes) -> bytes:
    """Encode a tiny RGBA image without adding Pillow to the sidecar."""
    rows = b"".join(b"\0" + rgba[index : index + width * 4] for index in range(0, len(rgba), width * 4))
    chunk = lambda kind, data: struct.pack(">I", len(data)) + kind + data + struct.pack(">I", zlib.crc32(kind + data) & 0xFFFFFFFF)
    return b"\x89PNG\r\n\x1a\n" + chunk(b"IHDR", struct.pack(">IIBBBBB", width, height, 8, 6, 0, 0, 0)) + chunk(b"IDAT", zlib.compress(rows, 9)) + chunk(b"IEND", b"")


if os.name == "nt":
    INVALID_FILE_ATTRIBUTES = 0xFFFFFFFF
    FILE_ATTRIBUTE_DIRECTORY = 0x10
    DRIVE_REMOTE = 4
    BI_RGB = 0
    DIB_RGB_COLORS = 0
    DI_NORMAL = 0x0003
    SHGFI_ICON = 0x000000100
    SHGFI_LARGEICON = 0x000000000

    class SHFILEINFOW(ctypes.Structure):
        _fields_ = [("hIcon", wintypes.HICON), ("iIcon", ctypes.c_int), ("dwAttributes", wintypes.DWORD), ("szDisplayName", wintypes.WCHAR * 260), ("szTypeName", wintypes.WCHAR * 80)]

    class BITMAPINFOHEADER(ctypes.Structure):
        _fields_ = [("biSize", wintypes.DWORD), ("biWidth", ctypes.c_long), ("biHeight", ctypes.c_long), ("biPlanes", wintypes.WORD), ("biBitCount", wintypes.WORD), ("biCompression", wintypes.DWORD), ("biSizeImage", wintypes.DWORD), ("biXPelsPerMeter", ctypes.c_long), ("biYPelsPerMeter", ctypes.c_long), ("biClrUsed", wintypes.DWORD), ("biClrImportant", wintypes.DWORD)]

    class BITMAPINFO(ctypes.Structure):
        _fields_ = [("bmiHeader", BITMAPINFOHEADER), ("bmiColors", wintypes.DWORD * 1)]

    shell32 = ctypes.WinDLL("shell32", use_last_error=True)
    user32 = ctypes.WinDLL("user32", use_last_error=True)
    gdi32 = ctypes.WinDLL("gdi32", use_last_error=True)
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)

    shell32.SHGetFileInfoW.argtypes = [wintypes.LPCWSTR, wintypes.DWORD, ctypes.POINTER(SHFILEINFOW), ctypes.c_uint, wintypes.UINT]
    shell32.SHGetFileInfoW.restype = ctypes.c_size_t
    user32.DrawIconEx.argtypes = [wintypes.HDC, ctypes.c_int, ctypes.c_int, wintypes.HICON, ctypes.c_int, ctypes.c_int, wintypes.UINT, wintypes.HBRUSH, wintypes.UINT]
    user32.DrawIconEx.restype = wintypes.BOOL
    user32.DestroyIcon.argtypes = [wintypes.HICON]
    user32.DestroyIcon.restype = wintypes.BOOL
    gdi32.CreateCompatibleDC.argtypes = [wintypes.HDC]
    gdi32.CreateCompatibleDC.restype = wintypes.HDC
    gdi32.CreateDIBSection.argtypes = [wintypes.HDC, ctypes.POINTER(BITMAPINFO), wintypes.UINT, ctypes.POINTER(ctypes.c_void_p), wintypes.HANDLE, wintypes.DWORD]
    gdi32.CreateDIBSection.restype = wintypes.HBITMAP
    gdi32.SelectObject.argtypes = [wintypes.HDC, wintypes.HGDIOBJ]
    gdi32.SelectObject.restype = wintypes.HGDIOBJ
    gdi32.DeleteObject.argtypes = [wintypes.HGDIOBJ]
    gdi32.DeleteObject.restype = wintypes.BOOL
    gdi32.DeleteDC.argtypes = [wintypes.HDC]
    gdi32.DeleteDC.restype = wintypes.BOOL
    kernel32.GetFileAttributesW.argtypes = [wintypes.LPCWSTR]
    kernel32.GetFileAttributesW.restype = wintypes.DWORD
    kernel32.GetDriveTypeW.argtypes = [wintypes.LPCWSTR]
    kernel32.GetDriveTypeW.restype = wintypes.UINT


def _safe_executable_path(value: str) -> str | None:
    """Return a local executable path that is safe to give to Shell APIs."""
    if os.name != "nt" or not isinstance(value, str) or not value or len(value) > 32767:
        return None
    path = os.path.abspath(value)
    drive, _ = os.path.splitdrive(path)
    if not drive or path.startswith("\\\\") or Path(path).suffix.lower() not in {".exe", ".com"}:
        return None
    # Do not let icon loading wait for an unreachable mapped/network drive.
    if kernel32.GetDriveTypeW(f"{drive}\\") == DRIVE_REMOTE:
        return None
    attributes = kernel32.GetFileAttributesW(path)
    if attributes == INVALID_FILE_ATTRIBUTES or attributes & FILE_ATTRIBUTE_DIRECTORY:
        return None
    return path


def executable_icon_data_url(executable: str) -> str:
    """Return a 32px PNG data URL, or an empty string when it cannot be read."""
    path = _safe_executable_path(executable)
    if not path:
        return ""

    info = SHFILEINFOW()
    if not shell32.SHGetFileInfoW(path, 0, ctypes.byref(info), ctypes.sizeof(info), SHGFI_ICON | SHGFI_LARGEICON) or not info.hIcon:
        return ""

    dc = bitmap = original = None
    try:
        bitmap_info = BITMAPINFO()
        bitmap_info.bmiHeader = BITMAPINFOHEADER(ctypes.sizeof(BITMAPINFOHEADER), ICON_SIZE, -ICON_SIZE, 1, 32, BI_RGB, 0, 0, 0, 0, 0)
        pixels = ctypes.c_void_p()
        dc = gdi32.CreateCompatibleDC(None)
        if not dc:
            return ""
        bitmap = gdi32.CreateDIBSection(dc, ctypes.byref(bitmap_info), DIB_RGB_COLORS, ctypes.byref(pixels), None, 0)
        if not bitmap or not pixels.value:
            return ""
        original = gdi32.SelectObject(dc, bitmap)
        if not original or not user32.DrawIconEx(dc, 0, 0, info.hIcon, ICON_SIZE, ICON_SIZE, 0, None, DI_NORMAL):
            return ""
        bgra = ctypes.string_at(pixels, ICON_SIZE * ICON_SIZE * 4)
        rgba = bytearray(ICON_SIZE * ICON_SIZE * 4)
        for index in range(0, len(bgra), 4):
            blue, green, red, alpha = bgra[index : index + 4]
            rgba[index : index + 4] = bytes((red, green, blue, alpha if alpha else 255 if (red or green or blue) else 0))
        return "data:image/png;base64," + base64.b64encode(_png_rgba(ICON_SIZE, ICON_SIZE, bytes(rgba))).decode("ascii")
    except (OSError, ValueError, ctypes.ArgumentError):
        return ""
    finally:
        if dc and original:
            gdi32.SelectObject(dc, original)
        if bitmap:
            gdi32.DeleteObject(bitmap)
        if dc:
            gdi32.DeleteDC(dc)
        user32.DestroyIcon(info.hIcon)


def _icon_cache_path(cache_dir: Path, executable: str) -> Path:
    key = hashlib.sha256(os.path.normcase(executable).encode("utf-8", "surrogatepass")).hexdigest()
    return cache_dir / f"{key}.json"


def _file_marker(executable: str) -> dict[str, int] | None:
    try:
        stat = os.stat(executable)
    except OSError:
        return None
    return {"size": stat.st_size, "mtime_ns": stat.st_mtime_ns}


def _load_cached_icon(cache_dir: Path | None, executable: str, marker: dict[str, int]) -> str | None:
    if cache_dir is None:
        return None
    try:
        path = _icon_cache_path(cache_dir, executable)
        if not path.is_file() or path.stat().st_size > 96 * 1024:
            return None
        item = json.loads(path.read_text(encoding="utf-8"))
        icon = item.get("icon")
        if (
            item.get("version") != ICON_CACHE_VERSION
            or item.get("marker") != marker
            or not isinstance(icon, str)
            or len(icon) > 80 * 1024
            or (icon and not icon.startswith("data:image/png;base64,"))
            or float(item.get("expires_at", 0)) <= time.time()
        ):
            return None
        return icon
    except (OSError, ValueError, TypeError, json.JSONDecodeError):
        return None


def _store_cached_icon(cache_dir: Path | None, executable: str, marker: dict[str, int], icon: str) -> None:
    if cache_dir is None:
        return
    try:
        cache_dir.mkdir(parents=True, exist_ok=True)
        ttl = ICON_CACHE_TTL_SECONDS if icon else ICON_FAILURE_CACHE_TTL_SECONDS
        payload = {"version": ICON_CACHE_VERSION, "marker": marker, "expires_at": time.time() + ttl, "icon": icon}
        target = _icon_cache_path(cache_dir, executable)
        temporary = target.with_suffix(".tmp")
        temporary.write_text(json.dumps(payload, separators=(",", ":")), encoding="utf-8")
        os.replace(temporary, target)
    except OSError:
        # Icons are only a presentation enhancement.  A read-only profile or a
        # transient disk error must not make the processes screen unavailable.
        return


def process_icons(processes: list[dict[str, object]], cache_dir: Path | None = None) -> list[dict[str, object]]:
    """Read a bounded, de-duplicated batch for the visible process cards."""
    results: list[dict[str, object]] = []
    seen: set[str] = set()
    for process in processes:
        if len(results) >= MAX_ICON_BATCH or not isinstance(process, dict):
            continue
        executable = str(process.get("exe") or "")
        key = os.path.normcase(executable)
        if not executable or key in seen:
            continue
        seen.add(key)
        safe_path = _safe_executable_path(executable)
        marker = _file_marker(safe_path) if safe_path else None
        icon = _load_cached_icon(cache_dir, safe_path, marker) if safe_path and marker else None
        if icon is None:
            icon = executable_icon_data_url(safe_path) if safe_path else ""
            if safe_path and marker:
                _store_cached_icon(cache_dir, safe_path, marker, icon)
        try:
            pid = int(process.get("pid") or 0)
        except (TypeError, ValueError):
            pid = 0
        results.append({"pid": pid, "exe": executable, "icon": icon})
    return results
