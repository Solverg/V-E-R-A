"""DPAPI-backed persistence for V.E.R.A. secrets (never expose values)."""
from __future__ import annotations

import base64
import ctypes
import sys
from ctypes import wintypes


class SecureStorageError(RuntimeError):
    pass


class DATA_BLOB(ctypes.Structure):
    _fields_ = [("cbData", wintypes.DWORD), ("pbData", ctypes.POINTER(ctypes.c_char))]


def _blob(value: bytes):
    buffer = ctypes.create_string_buffer(value)
    return DATA_BLOB(len(value), ctypes.cast(buffer, ctypes.POINTER(ctypes.c_char))), buffer


def _read(blob: DATA_BLOB) -> bytes:
    try:
        return ctypes.string_at(blob.pbData, blob.cbData)
    finally:
        ctypes.windll.kernel32.LocalFree(blob.pbData)


def protect_text(value: str) -> str:
    if sys.platform != "win32":
        raise SecureStorageError("DPAPI доступен только в Windows.")
    source, keepalive = _blob(value.encode("utf-8"))
    target = DATA_BLOB()
    if not ctypes.windll.crypt32.CryptProtectData(ctypes.byref(source), None, None, None, None, 0, ctypes.byref(target)):
        raise SecureStorageError("Не удалось защитить ключ через DPAPI.")
    del keepalive
    return base64.b64encode(_read(target)).decode("ascii")


def unprotect_text(value: str) -> str:
    if sys.platform != "win32":
        raise SecureStorageError("DPAPI доступен только в Windows.")
    try:
        encrypted = base64.b64decode(value.encode("ascii"), validate=True)
    except Exception as exc:
        raise SecureStorageError("Повреждён защищённый ключ.") from exc
    source, keepalive = _blob(encrypted)
    target = DATA_BLOB()
    if not ctypes.windll.crypt32.CryptUnprotectData(ctypes.byref(source), None, None, None, None, 0, ctypes.byref(target)):
        raise SecureStorageError("Не удалось открыть ключ через DPAPI.")
    del keepalive
    return _read(target).decode("utf-8")
