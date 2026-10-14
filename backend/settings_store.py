"""Non-secret V.E.R.A. preferences and DPAPI-protected provider keys."""
from __future__ import annotations
import json
from pathlib import Path
from typing import Any
from backend.secure_storage import SecureStorageError, protect_text, unprotect_text

SECRET_KEYS={"gemini_api_key","groq_api_key"}
SCAN_INTERVALS=(30,60,180,300,600)
# These are stable text models that are currently available to new projects.
# Do not make preview IDs the default: their retirement breaks saved settings.
DEFAULTS={"provider":"gemini","gemini_model":"gemini-3.5-flash-lite","groq_model":"openai/gpt-oss-20b","scan_interval_sec":30,"monitoring_enabled":False,"autostart":False,"minimize_to_tray":True,"show_notifications":True,"auto_download_updates":True,"pending_update_version":"","secrets":{}}

def normalize_scan_interval(value: Any) -> int:
    """Return the supported interval closest to a legacy seconds value."""
    try:
        seconds=int(value)
    except (TypeError,ValueError):
        seconds=DEFAULTS["scan_interval_sec"]
    return min(SCAN_INTERVALS,key=lambda interval:(abs(interval-seconds),interval))

class SettingsStore:
    def __init__(self, data_dir: Path): self.path=data_dir/"settings.json"; self.data=self._load()
    def _load(self):
        data=dict(DEFAULTS); data["secrets"]={}
        migrated_interval=False
        try:
            raw=json.loads(self.path.read_text(encoding="utf-8"))
            if isinstance(raw,dict):
                for key,value in raw.items():
                    if key not in SECRET_KEYS: data[key]=value
                # Monitoring used to be implicit whenever process rules
                # existed. Preserve that behavior for a pre-monitoring
                # settings file; otherwise every migrated rule would look
                # active but never be enforced.
                if "monitoring_enabled" not in raw:
                    data["monitoring_enabled"]=True
                # upgrade earlier plaintext keys by encrypting on the next set/save
                for key in SECRET_KEYS:
                    if raw.get(key): data.setdefault("_legacy",{})[key]=str(raw[key])
        except (OSError,json.JSONDecodeError): pass
        data["secrets"] = data.get("secrets") if isinstance(data.get("secrets"),dict) else {}
        normalized_interval=normalize_scan_interval(data.get("scan_interval_sec"))
        migrated_interval=data.get("scan_interval_sec") != normalized_interval
        data["scan_interval_sec"]=normalized_interval
        if migrated_interval:
            # Persist the selected option so monitoring and the UI agree after
            # upgrade, even before the user next edits the settings.
            self.data=data
            self._save()
        return data
    def _save(self):
        self.path.parent.mkdir(parents=True,exist_ok=True)
        outgoing={k:v for k,v in self.data.items() if k not in SECRET_KEYS and k!="_legacy"}
        self.path.write_text(json.dumps(outgoing,ensure_ascii=False,indent=2),encoding="utf-8")
    def public(self):
        public={key:value for key,value in self.data.items() if key not in {"secrets","_legacy"}}
        # The UI needs an unambiguous saved/not-saved state, but must never
        # receive the secret itself.
        public["has_gemini_api_key"]=bool((self.data.get("_legacy") or {}).get("gemini_api_key") or self.data["secrets"].get("gemini_api_key"))
        public["has_groq_api_key"]=bool((self.data.get("_legacy") or {}).get("groq_api_key") or self.data["secrets"].get("groq_api_key"))
        return public
    def secret(self,key):
        legacy=(self.data.get("_legacy") or {}).get(key)
        if legacy: return legacy
        record=self.data["secrets"].get(key) or {}
        try: return unprotect_text(record.get("value", "")) if record.get("provider")=="windows-dpapi" else ""
        except SecureStorageError: return ""
    def set(self, values:dict[str,Any]):
        clear_secrets=set(values.pop("clear_secrets",[]) or [])
        for key,value in values.items():
            if key in SECRET_KEYS:
                # Empty fields are normal after a reload because protected
                # values are intentionally never returned to the UI.  Treat an
                # empty value as "keep", and only delete via an explicit
                # clear request.
                if not value:
                    continue
                self.data.get("_legacy",{}).pop(key,None)
                if value:
                    try: self.data["secrets"][key]={"provider":"windows-dpapi","value":protect_text(str(value))}
                    except SecureStorageError as exc: raise ValueError("Не удалось безопасно сохранить API-ключ.") from exc
            elif key in DEFAULTS and key != "secrets": self.data[key]=value
        for key in clear_secrets:
            if key in SECRET_KEYS:
                self.data.get("_legacy",{}).pop(key,None)
                self.data["secrets"].pop(key,None)
        self.data["scan_interval_sec"]=normalize_scan_interval(self.data.get("scan_interval_sec"))
        self.data["monitoring_enabled"]=bool(self.data.get("monitoring_enabled"))
        self.data["auto_download_updates"]=bool(self.data.get("auto_download_updates"))
        self.data["pending_update_version"]=str(self.data.get("pending_update_version") or "")
        self._save(); return self.public()
