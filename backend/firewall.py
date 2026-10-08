"""Safe, V.E.R.A.-scoped management of Windows Firewall application rules."""
from __future__ import annotations

import ipaddress
import json
import re
import subprocess
import uuid
from pathlib import Path
from typing import Any


RULE_PREFIX = "V.E.R.A. Firewall"
PROTOCOLS = {"any", "tcp", "udp"}
DIRECTIONS = {"outbound": "out", "inbound": "in"}
ACTIONS = {"allow", "block"}
PROFILES = {"any", "domain", "private", "public"}
PORTS_RE = re.compile(r"^\d{1,5}(?:-\d{1,5})?(?:,\d{1,5}(?:-\d{1,5})?)*$")


class FirewallManager:
    """Persist only V.E.R.A.-owned rules and call netsh without a shell."""

    def __init__(self, data_dir: Path):
        self.path = data_dir / "firewall_rules.json"
        self.data_dir = data_dir

    def _load(self) -> dict[str, dict[str, Any]]:
        try:
            raw = json.loads(self.path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            return {}
        if not isinstance(raw, list):
            return {}
        return {str(item["id"]): item for item in raw if isinstance(item, dict) and item.get("id") and item.get("system_name", "").startswith(RULE_PREFIX)}

    def _save(self, rules: dict[str, dict[str, Any]]) -> None:
        self.data_dir.mkdir(parents=True, exist_ok=True)
        payload = sorted(rules.values(), key=lambda item: (str(item.get("label", "")).lower(), str(item["id"])))
        self.path.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")

    @staticmethod
    def _run_netsh(arguments: list[str]) -> None:
        try:
            result = subprocess.run(["netsh", *arguments], capture_output=True, text=True, encoding="utf-8", errors="replace", check=False, timeout=15)
        except FileNotFoundError as exc:
            raise RuntimeError("Windows Firewall недоступен: не найдена команда netsh.") from exc
        except subprocess.TimeoutExpired as exc:
            raise RuntimeError("Windows Firewall не ответил вовремя.") from exc
        if result.returncode == 0:
            return
        output = (result.stderr or result.stdout or "").strip()
        lowered = output.lower()
        if "access is denied" in lowered or "отказано в доступе" in lowered or "requires elevation" in lowered:
            raise PermissionError("Для изменения Firewall запустите V.E.R.A. от имени администратора.")
        raise RuntimeError(output or "Не удалось изменить правило Windows Firewall.")

    @staticmethod
    def _ports(value: str) -> str:
        value = str(value or "").strip()
        if not value or value.lower() == "any":
            return "any"
        if not PORTS_RE.fullmatch(value):
            raise ValueError("Порты укажите числами: 443, 80-90 или any.")
        for chunk in value.split(","):
            for port in chunk.split("-"):
                if not 1 <= int(port) <= 65535:
                    raise ValueError("Номер порта должен быть от 1 до 65535.")
        return value

    @staticmethod
    def _remote_addresses(value: str) -> str:
        value = str(value or "").strip()
        if not value or value.lower() == "any":
            return "any"
        addresses = [part.strip() for part in value.split(",")]
        try:
            return ",".join(str(ipaddress.ip_address(address)) for address in addresses)
        except ValueError as exc:
            raise ValueError("Удалённые адреса укажите как IP через запятую или any.") from exc

    @staticmethod
    def _label(value: str) -> str:
        label = " ".join(str(value or "").split())[:80]
        if not label:
            raise ValueError("Укажите название правила.")
        return label

    def list(self) -> list[dict[str, Any]]:
        return list(self._load().values())

    def create(self, values: dict[str, Any]) -> dict[str, Any]:
        program = Path(str(values.get("program") or "").strip())
        if not program.is_file() or program.suffix.lower() != ".exe":
            raise ValueError("Укажите существующий .exe-файл программы.")
        action = str(values.get("action") or "block").lower()
        direction = str(values.get("direction") or "outbound").lower()
        protocol = str(values.get("protocol") or "any").lower()
        profile = str(values.get("profile") or "any").lower()
        if action not in ACTIONS or direction not in DIRECTIONS or protocol not in PROTOCOLS or profile not in PROFILES:
            raise ValueError("Недопустимые параметры правила Firewall.")
        rule_id = uuid.uuid4().hex[:12]
        record = {
            "id": rule_id,
            "system_name": f"{RULE_PREFIX} #{rule_id}",
            "label": self._label(values.get("label") or program.stem),
            "program": str(program),
            "action": action,
            "direction": direction,
            "protocol": protocol,
            "local_port": self._ports(values.get("local_port", "")),
            "remote_ip": self._remote_addresses(values.get("remote_ip", "")),
            "profile": profile,
            "enabled": True,
        }
        self._run_netsh([
            "advfirewall", "firewall", "add", "rule", f"name={record['system_name']}", f"dir={DIRECTIONS[direction]}",
            f"action={action}", f"program={record['program']}", f"enable=yes", f"profile={profile}",
            f"protocol={protocol.upper()}", f"localport={record['local_port']}", f"remoteip={record['remote_ip']}",
        ])
        rules = self._load(); rules[rule_id] = record; self._save(rules)
        return record

    def toggle(self, rule_id: str) -> dict[str, Any]:
        rules = self._load(); record = rules.get(str(rule_id))
        if not record:
            raise ValueError("Правило Firewall не найдено.")
        enabled = not bool(record.get("enabled"))
        self._run_netsh(["advfirewall", "firewall", "set", "rule", f"name={record['system_name']}", f"new", f"enable={'yes' if enabled else 'no'}"])
        record["enabled"] = enabled; rules[str(rule_id)] = record; self._save(rules)
        return record

    def delete(self, rule_id: str) -> bool:
        rules = self._load(); record = rules.get(str(rule_id))
        if not record:
            raise ValueError("Правило Firewall не найдено.")
        self._run_netsh(["advfirewall", "firewall", "delete", "rule", f"name={record['system_name']}"])
        del rules[str(rule_id)]; self._save(rules)
        return True
