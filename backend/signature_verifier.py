"""Windows Authenticode signature verification for V.E.R.A.'s backend."""

from __future__ import annotations

import ctypes
import os
import sys
import threading
from ctypes import wintypes
from dataclasses import dataclass


STATUS_VERIFIED = "verified"
STATUS_UNKNOWN = "unknown"
_MAX_CACHE_SIZE = 1024
_cache_lock = threading.RLock()
_signature_cache: dict[tuple[str, int, int], "SignatureVerification"] = {}


@dataclass(frozen=True)
class SignatureVerification:
    status: str
    is_signed: bool
    error_code: int | None = None


def verify_executable_signature(path: str) -> SignatureVerification:
    """Return ``verified`` only when Windows trusts an executable signature."""
    if sys.platform != "win32" or not path:
        return SignatureVerification(STATUS_UNKNOWN, False)
    try:
        normalized_path = os.path.normcase(os.path.abspath(path))
        stat = os.stat(normalized_path)
    except OSError:
        return SignatureVerification(STATUS_UNKNOWN, False)

    cache_key = (normalized_path, stat.st_size, stat.st_mtime_ns)
    with _cache_lock:
        if cached := _signature_cache.get(cache_key):
            return cached

    error_code = _win_verify_trust(normalized_path)
    result = SignatureVerification(STATUS_VERIFIED if error_code == 0 else STATUS_UNKNOWN, error_code not in _NO_SIGNATURE_ERRORS, error_code)
    with _cache_lock:
        if len(_signature_cache) >= _MAX_CACHE_SIZE:
            _signature_cache.pop(next(iter(_signature_cache)))
        _signature_cache[cache_key] = result
    return result


def clear_signature_cache() -> None:
    with _cache_lock:
        _signature_cache.clear()


class GUID(ctypes.Structure):
    _fields_ = [("Data1", wintypes.DWORD), ("Data2", wintypes.WORD), ("Data3", wintypes.WORD), ("Data4", wintypes.BYTE * 8)]


class WINTRUST_FILE_INFO(ctypes.Structure):
    _fields_ = [("cbStruct", wintypes.DWORD), ("pcwszFilePath", wintypes.LPCWSTR), ("hFile", wintypes.HANDLE), ("pgKnownSubject", ctypes.POINTER(GUID))]


class WINTRUST_DATA(ctypes.Structure):
    _fields_ = [("cbStruct", wintypes.DWORD), ("pPolicyCallbackData", wintypes.LPVOID), ("pSIPClientData", wintypes.LPVOID), ("dwUIChoice", wintypes.DWORD), ("fdwRevocationChecks", wintypes.DWORD), ("dwUnionChoice", wintypes.DWORD), ("pFile", ctypes.POINTER(WINTRUST_FILE_INFO)), ("dwStateAction", wintypes.DWORD), ("hWVTStateData", wintypes.HANDLE), ("pwszURLReference", wintypes.LPCWSTR), ("dwProvFlags", wintypes.DWORD), ("dwUIContext", wintypes.DWORD), ("pSignatureSettings", wintypes.LPVOID)]


WINTRUST_ACTION_GENERIC_VERIFY_V2 = GUID(0x00AAC56B, 0xCD44, 0x11D0, (wintypes.BYTE * 8)(0x8C, 0xC2, 0x00, 0xC0, 0x4F, 0xC2, 0x95, 0xEE))
WTD_UI_NONE, WTD_REVOKE_NONE, WTD_CHOICE_FILE, WTD_STATEACTION_IGNORE = 2, 0, 1, 0
WTD_CACHE_ONLY_URL_RETRIEVAL = 0x00001000
_NO_SIGNATURE_ERRORS = {-2146762751, -2146762750, -2146762749, -2146762496, -2146885629}


def _win_verify_trust(path: str) -> int:
    file_info = WINTRUST_FILE_INFO(ctypes.sizeof(WINTRUST_FILE_INFO), path, None, None)
    trust_data = WINTRUST_DATA(ctypes.sizeof(WINTRUST_DATA), None, None, WTD_UI_NONE, WTD_REVOKE_NONE, WTD_CHOICE_FILE, ctypes.pointer(file_info), WTD_STATEACTION_IGNORE, None, None, WTD_CACHE_ONLY_URL_RETRIEVAL, 0, None)
    win_verify_trust = ctypes.windll.wintrust.WinVerifyTrust
    win_verify_trust.argtypes = [wintypes.HWND, ctypes.POINTER(GUID), ctypes.POINTER(WINTRUST_DATA)]
    win_verify_trust.restype = wintypes.LONG
    return int(win_verify_trust(None, ctypes.byref(WINTRUST_ACTION_GENERIC_VERIFY_V2), ctypes.byref(trust_data)))
