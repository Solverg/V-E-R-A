"""Non-secret V.E.R.A. preferences and DPAPI-protected provider keys."""
from __future__ import annotations
import json
from pathlib import Path
from typing import Any
from backend.secure_storage import SecureStorageError, protect_text, unprotect_text

SECRET_KEYS={"gemini_api_key","groq_api_key"}
DEFAULTS={"provider":"gemini","gemini_model":"gemini-3.1-flash-preview","scan_interval_sec":5,"monitoring_enabled":False,"autostart":False,"minimize_to_tray":True,"show_notifications":True,"secrets":{}}

class SettingsStore:
    def __init__(self, data_dir: Path): self.path=data_dir/"settings.json"; self.data=self._load()
    def _load(self):
        data=dict(DEFAULTS); data["secrets"]={}
        try:
            raw=json.loads(self.path.read_text(encoding="utf-8"))
            if isinstance(raw,dict):
                for key,value in raw.items():
                    if key not in SECRET_KEYS: data[key]=value
                # upgrade earlier plaintext keys by encrypting on the next set/save
                for key in SECRET_KEYS:
                    if raw.get(key): data.setdefault("_legacy",{})[key]=str(raw[key])
        except (OSError,json.JSONDecodeError): pass
        data["secrets"] = data.get("secrets") if isinstance(data.get("secrets"),dict) else {}
        return data
    def _save(self):
        self.path.parent.mkdir(parents=True,exist_ok=True)
        outgoing={k:v for k,v in self.data.items() if k not in SECRET_KEYS and k!="_legacy"}
        self.path.write_text(json.dumps(outgoing,ensure_ascii=False,indent=2),encoding="utf-8")
    def public(self):
        return {key:value for key,value in self.data.items() if key not in {"secrets","_legacy"}}
    def secret(self,key):
        legacy=(self.data.get("_legacy") or {}).get(key)
        if legacy: return legacy
        record=self.data["secrets"].get(key) or {}
        try: return unprotect_text(record.get("value", "")) if record.get("provider")=="windows-dpapi" else ""
        except SecureStorageError: return ""
    def set(self, values:dict[str,Any]):
        for key,value in values.items():
            if key in SECRET_KEYS:
                self.data.get("_legacy",{}).pop(key,None)
                if value:
                    try: self.data["secrets"][key]={"provider":"windows-dpapi","value":protect_text(str(value))}
                    except SecureStorageError as exc: raise ValueError("Не удалось безопасно сохранить API-ключ.") from exc
                else: self.data["secrets"].pop(key,None)
            elif key in DEFAULTS and key != "secrets": self.data[key]=value
        self.data["scan_interval_sec"]=max(1,min(60,int(self.data.get("scan_interval_sec",5))))
        self.data["monitoring_enabled"]=bool(self.data.get("monitoring_enabled"))
        self._save(); return self.public()
