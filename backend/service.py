"""Small, dependency-light JSON backend for the Tauri migration.

The legacy PyQt application owns both widgets and business logic.  This module
is deliberately UI-free so it can be packaged as a Tauri sidecar and reused by
tests.  Each invocation handles one JSON request and prints one JSON response.
"""

from __future__ import annotations

import argparse
import json
import os
import shutil
import sys
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

import psutil

from backend.signature_verifier import STATUS_VERIFIED, verify_executable_signature
from backend.network import list_connections, public_ip
from backend.settings_store import SettingsStore
from backend.startup import StartupManager
from backend.assistant import cached_description, chat, describe
from backend.firewall import FirewallManager
from backend.windows_icons import process_icons


DATA_DIR_ENV = "VERA_DATA_DIR"
LEGACY_DATA_DIR_ENV = "KRISTINA_DATA_DIR"
DEFAULT_DATA_DIR = Path.home() / ".vera"
LEGACY_DATA_DIR = Path.home() / ".kristina_helper"


def resolve_data_dir() -> Path:
    """Always create V.E.R.A. data; migrate legacy files once when needed."""
    if configured := os.environ.get(DATA_DIR_ENV):
        return Path(configured)
    if legacy_configured := os.environ.get(LEGACY_DATA_DIR_ENV):
        return Path(legacy_configured)
    return DEFAULT_DATA_DIR


@dataclass
class BlockRule:
    name: str
    enabled: bool = True
    kill_count: int = 0
    mode: str = "permanent"
    exe_path: str = ""


class BackendService:
    """JSON-backed process and block-rule operations with no GUI dependency."""

    def __init__(self, data_dir: Path | None = None):
        self.data_dir = data_dir or resolve_data_dir()
        self._migrate_legacy_data()
        self.rules_path = self.data_dir / "blocked.json"
        self.settings = SettingsStore(self.data_dir)
        self.firewall = FirewallManager(self.data_dir)
        self.session_kills = 0

    def _migrate_legacy_data(self) -> None:
        """Copy only known data files; never make old data the active location."""
        if self.data_dir != DEFAULT_DATA_DIR or not LEGACY_DATA_DIR.is_dir():
            return
        self.data_dir.mkdir(parents=True, exist_ok=True)
        for name in ("blocked.json", "settings.json", "descriptions.json"):
            target, source = self.data_dir / name, LEGACY_DATA_DIR / name
            if source.is_file() and not target.exists():
                try: shutil.copy2(source, target)
                except OSError: pass

    @staticmethod
    def rule_key(name: str, exe_path: str = "") -> str:
        name_key = str(name or "").strip().lower()
        path_key = str(exe_path or "").strip().lower()
        return f"{name_key}|{path_key}" if path_key else name_key

    def _load_rules(self) -> dict[str, BlockRule]:
        if not self.rules_path.exists():
            return {}
        try:
            raw_rules = json.loads(self.rules_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            return {}

        rules: dict[str, BlockRule] = {}
        if not isinstance(raw_rules, list):
            return rules
        for raw in raw_rules:
            if not isinstance(raw, dict) or not raw.get("name"):
                continue
            rule = BlockRule(
                name=str(raw["name"]),
                enabled=bool(raw.get("enabled", True)),
                kill_count=max(0, int(raw.get("kill_count", 0))),
                mode="kill_on_launch" if raw.get("mode") == "kill_on_launch" else "permanent",
                exe_path=str(raw.get("exe_path") or ""),
            )
            rules[self.rule_key(rule.name, rule.exe_path)] = rule
        return rules

    def _save_rules(self, rules: dict[str, BlockRule]) -> None:
        self.data_dir.mkdir(parents=True, exist_ok=True)
        payload = [asdict(rule) for rule in sorted(rules.values(), key=lambda item: item.name.lower())]
        self.rules_path.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")

    def list_rules(self) -> list[dict[str, Any]]:
        descriptions_path = self.data_dir / "descriptions.json"
        rules: list[dict[str, Any]] = []
        for rule in self._load_rules().values():
            item = asdict(rule)
            description = cached_description(descriptions_path, rule.name, rule.exe_path) or {}
            item["description"] = str(description.get("description") or "")
            item["description_status"] = str(description.get("status") or "unknown")
            rules.append(item)
        return rules

    def list_processes(self) -> list[dict[str, Any]]:
        rules = self._load_rules()
        descriptions_path = self.data_dir / "descriptions.json"
        processes: list[dict[str, Any]] = []
        for process in psutil.process_iter(["pid", "name", "exe", "status", "cpu_percent", "memory_info"]):
            try:
                info = process.info
                name = str(info.get("name") or "")
                exe_path = str(info.get("exe") or "")
                exact_rule = rules.get(self.rule_key(name, exe_path))
                rule = exact_rule or rules.get(self.rule_key(name))
                memory = info.get("memory_info")
                description = cached_description(descriptions_path, name, exe_path) or {}
                processes.append(
                    {
                        "pid": int(info["pid"]),
                        "name": name or "System process",
                        "exe": exe_path,
                        "status": str(info.get("status") or ""),
                        "cpu_percent": round(float(info.get("cpu_percent") or 0), 1),
                        "memory_mb": round((memory.rss / 1024 / 1024) if memory else 0, 1),
                        "is_blocked": bool(rule and rule.enabled),
                        # The frontend needs the policy to distinguish the two
                        # rule types; a boolean alone loses that information.
                        "block_mode": rule.mode if rule and rule.enabled else "",
                        # Reuse the matching rule key when a user changes its
                        # mode.  This preserves migrated name-only rules.
                        "block_rule_exe_path": rule.exe_path if rule and rule.enabled else "",
                        # Signature verification is deferred until this row is visible in the UI.
                        "security_status": "unchecked",
                        "description": description.get("description", ""),
                        "description_status": description.get("status", "unknown"),
                    }
                )
            except (psutil.NoSuchProcess, psutil.AccessDenied, OSError):
                continue
        return sorted(processes, key=lambda item: (item["name"].lower(), item["pid"]))

    def verify_process_signatures(self, processes: list[dict[str, Any]]) -> list[dict[str, Any]]:
        """Verify a small, visible batch without delaying the process snapshot."""
        verified: list[dict[str, Any]] = []
        for process in processes[:32]:
            if not isinstance(process, dict):
                continue
            exe_path = str(process.get("exe") or "")
            try:
                pid = int(process.get("pid") or 0)
            except (TypeError, ValueError):
                pid = 0
            signature = verify_executable_signature(exe_path)
            verified.append(
                {
                    "pid": pid,
                    "exe": exe_path,
                    "security_status": "verified" if signature.status == STATUS_VERIFIED else "unknown",
                }
            )
        return verified

    def upsert_rule(self, name: str, mode: str = "permanent", exe_path: str = "") -> dict[str, Any]:
        clean_name = str(name or "").strip()
        if not clean_name:
            raise ValueError("У правила должно быть имя процесса.")
        rules = self._load_rules()
        key = self.rule_key(clean_name, exe_path)
        rule = rules.get(key) or BlockRule(name=clean_name, exe_path=str(exe_path or ""))
        rule.enabled = True
        rule.mode = "kill_on_launch" if mode == "kill_on_launch" else "permanent"
        rules[key] = rule
        self._save_rules(rules)
        return asdict(rule)

    def toggle_rule(self, name: str, exe_path: str = "") -> dict[str, Any]:
        rules = self._load_rules()
        rule = rules.get(self.rule_key(name, exe_path)) or rules.get(self.rule_key(name))
        if rule is None:
            raise ValueError("Правило не найдено.")
        rule.enabled = not rule.enabled
        rules[self.rule_key(rule.name, rule.exe_path)] = rule
        self._save_rules(rules)
        return asdict(rule)

    def delete_rule(self, name: str, exe_path: str = "") -> bool:
        rules = self._load_rules()
        key = self.rule_key(name, exe_path)
        if key not in rules:
            key = self.rule_key(name)
        if key not in rules:
            return False
        del rules[key]
        self._save_rules(rules)
        return True

    def terminate_process(self, pid: int, name: str = "", exe_path: str = "") -> bool:
        if pid <= 0:
            raise ValueError("Некорректный PID.")
        try:
            process = psutil.Process(pid)
            if name and process.name().lower() != name.lower():
                raise ValueError("PID уже принадлежит другому процессу.")
            if exe_path and os.path.normcase(process.exe()) != os.path.normcase(exe_path):
                raise ValueError("Путь процесса изменился до завершения.")
            process.terminate()
            try:
                process.wait(timeout=3)
            except psutil.TimeoutExpired:
                process.kill()
                process.wait(timeout=3)
            return True
        except psutil.NoSuchProcess:
            return False
        except (psutil.AccessDenied, psutil.TimeoutExpired) as exc:
            raise ValueError(f"Не удалось завершить процесс: {exc}") from exc

    def enforce_processes(self, launch_cycle: bool = False) -> dict[str, int]:
        """Enforce matching rules with a PID/name/path revalidation immediately before kill."""
        rules = self._load_rules()
        killed = 0
        for process in psutil.process_iter(["pid", "name", "exe"]):
            try:
                info = process.info
                pid = int(info["pid"])
                name = str(info.get("name") or "") or "System process"
                exe_path = str(info.get("exe") or "")
            except (psutil.NoSuchProcess, psutil.AccessDenied, OSError, TypeError, ValueError):
                continue

            rule = rules.get(self.rule_key(name, exe_path)) or rules.get(self.rule_key(name))
            if not rule or not rule.enabled or (rule.mode == "kill_on_launch" and not launch_cycle):
                continue
            try:
                if self.terminate_process(pid, name, exe_path):
                    killed += 1
                    rule.kill_count += 1
            except ValueError:
                continue
        if killed:
            self._save_rules(rules)
        self.session_kills += killed
        return {"terminated": killed, "session_terminated": self.session_kills}

    def statistics(self) -> dict[str, int]:
        return self._statistics_for(self.list_processes())

    def _statistics_for(self, processes: list[dict[str, Any]]) -> dict[str, int]:
        """Build dashboard metrics from an already-collected process snapshot."""
        rules = self._load_rules().values()
        return {"total_processes": len(processes), "active_rules": sum(1 for x in rules if x.enabled), "active_blocked_processes": sum(1 for x in processes if x["is_blocked"]), "session_terminated": self.session_kills}

    def process_snapshot(self) -> dict[str, Any]:
        """Collect the process table and its metrics in one expensive scan."""
        processes = self.list_processes()
        return {"processes": processes, "statistics": self._statistics_for(processes)}

    def handle(self, request: dict[str, Any]) -> dict[str, Any]:
        action = request.get("action")
        if action == "health":
            return {"ok": True, "data": {"service": "vera-backend", "version": 1}}
        if action == "processes.list":
            return {"ok": True, "data": self.list_processes()}
        if action == "processes.snapshot":
            return {"ok": True, "data": self.process_snapshot()}
        if action == "processes.verify_signatures":
            return {"ok": True, "data": self.verify_process_signatures(list(request.get("processes") or []))}
        if action == "processes.icons":
            # Icons are extracted only for the visible, bounded UI batch.
            # Doing it while collecting every process would slow each refresh.
            return {"ok": True, "data": process_icons(list(request.get("processes") or []), self.data_dir / "icon-cache")}
        if action == "rules.list":
            return {"ok": True, "data": self.list_rules()}
        if action == "rules.upsert":
            return {"ok": True, "data": self.upsert_rule(request.get("name", ""), request.get("mode", "permanent"), request.get("exe_path", ""))}
        if action == "rules.toggle":
            return {"ok": True, "data": self.toggle_rule(request.get("name", ""), request.get("exe_path", ""))}
        if action == "rules.delete":
            return {"ok": True, "data": self.delete_rule(request.get("name", ""), request.get("exe_path", ""))}
        if action == "process.terminate":
            return {"ok": True, "data": self.terminate_process(int(request.get("pid", 0)), request.get("name", ""), request.get("exe_path", ""))}
        if action == "processes.enforce":
            return {"ok": True, "data": self.enforce_processes(bool(request.get("launch_cycle", False)))}
        if action == "processes.statistics":
            return {"ok": True, "data": self.statistics()}
        if action == "network.list":
            return {"ok": True, "data": list_connections()}
        if action == "network.public_ip":
            return {"ok": True, "data": public_ip()}
        if action == "firewall.list":
            return {"ok": True, "data": self.firewall.list()}
        if action == "firewall.create":
            return {"ok": True, "data": self.firewall.create(dict(request.get("values") or {}))}
        if action == "firewall.toggle":
            return {"ok": True, "data": self.firewall.toggle(str(request.get("id") or ""))}
        if action == "firewall.delete":
            return {"ok": True, "data": self.firewall.delete(str(request.get("id") or ""))}
        if action == "startup.list":
            return {"ok": True, "data": StartupManager.list()}
        if action == "startup.toggle":
            return {"ok": True, "data": StartupManager.toggle(dict(request.get("item") or {}))}
        if action == "app_autostart.get":
            return {"ok": True, "data": {"enabled": StartupManager.app_autostart()}}
        if action == "app_autostart.set":
            return {"ok": True, "data": {"enabled": StartupManager.app_autostart(bool(request.get("enabled")), str(request.get("command") or ""))}}
        if action == "settings.get":
            return {"ok": True, "data": self.settings.public()}
        if action == "settings.set":
            return {"ok": True, "data": self.settings.set(dict(request.get("values") or {}))}
        if action == "assistant.chat":
            return {"ok": True, "data": chat(self.settings, list(request.get("history") or []), str(request.get("message") or ""))}
        if action == "process.describe":
            return {"ok": True, "data": describe(self.settings, self.data_dir / "descriptions.json", str(request.get("name") or ""), str(request.get("exe_path") or ""), str(request.get("security_status") or "unknown"), bool(request.get("force")))}
        raise ValueError("Неизвестная команда backend-а.")


def main() -> int:
    # The Tauri host decodes the sidecar protocol as UTF-8.  Windows console
    # defaults can otherwise encode Russian messages as a legacy code page.
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="strict")
    except AttributeError:
        pass
    parser = argparse.ArgumentParser(description="V.E.R.A. Tauri backend")
    parser.add_argument("--request", required=True, help="One JSON request")
    args = parser.parse_args()
    try:
        response = BackendService().handle(json.loads(args.request))
    except (ValueError, TypeError, json.JSONDecodeError, PermissionError, RuntimeError) as exc:
        response = {"ok": False, "error": str(exc)}
    print(json.dumps(response, ensure_ascii=False), flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
