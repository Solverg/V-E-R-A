"""Safe, V.E.R.A.-scoped management of Windows Firewall application rules."""
from __future__ import annotations

import base64
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
        rules = {
            str(item["id"]): item
            for item in raw
            if isinstance(item, dict) and item.get("id") and item.get("system_name", "").startswith(RULE_PREFIX)
        }
        # Files created before remote-port support must retain their previous
        # "any remote port" meaning when they are listed or edited.
        for record in rules.values():
            record.setdefault("remote_port", "any")
        return rules

    def _save(self, rules: dict[str, dict[str, Any]]) -> None:
        self.data_dir.mkdir(parents=True, exist_ok=True)
        payload = sorted(rules.values(), key=lambda item: (str(item.get("label", "")).lower(), str(item["id"])))
        self.path.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")

    @staticmethod
    def _command_output(result: subprocess.CompletedProcess[str]) -> str:
        return (result.stderr or result.stdout or "").strip()

    @staticmethod
    def _requires_elevation(output: str) -> bool:
        lowered = output.lower()
        return any(marker in lowered for marker in (
            "access is denied",
            "отказано в доступе",
            "requires elevation",
            "elevation required",
            "требуются повышенные права",
            "требует повышения прав",
            "запрошенная операция требует повышения",
        ))

    @staticmethod
    def _uac_was_cancelled(returncode: int, output: str) -> bool:
        lowered = output.lower()
        return returncode == 1223 or any(marker in lowered for marker in (
            "operation was canceled",
            "operation was cancelled",
            "операция отменена",
            "отменено пользователем",
        ))

    @staticmethod
    def _run_elevated_netsh(arguments: list[str]) -> subprocess.CompletedProcess[str]:
        """Run one validated netsh command through the Windows UAC prompt.

        The command arguments are passed as Base64 JSON to the elevated
        PowerShell process.  That avoids command-line interpolation: a file
        name, label, or address can never become PowerShell syntax.
        """
        payload = base64.b64encode(json.dumps(arguments, ensure_ascii=False).encode("utf-8")).decode("ascii")
        elevated_script = (
            "$ErrorActionPreference='Stop';"
            f"$payload='{payload}';"
            "$netshArguments=@([Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($payload)) | ConvertFrom-Json);"
            "& netsh.exe @netshArguments;"
            "exit $LASTEXITCODE"
        )
        encoded_script = base64.b64encode(elevated_script.encode("utf-16le")).decode("ascii")
        launcher_script = (
            "$OutputEncoding=[Console]::OutputEncoding=[Text.UTF8Encoding]::new();"
            "$ErrorActionPreference='Stop';"
            "try {"
            "$process=Start-Process -FilePath 'powershell.exe' -Verb RunAs -Wait -PassThru -WindowStyle Hidden "
            f"-ArgumentList @('-NoProfile','-NonInteractive','-ExecutionPolicy','Bypass','-EncodedCommand','{encoded_script}');"
            "exit [int]$process.ExitCode"
            "} catch {"
            "$message=$_.Exception.Message;[Console]::Error.WriteLine($message);"
            "if($_.Exception.NativeErrorCode -eq 1223 -or $message -match 'cancel'){exit 1223};exit 1"
            "}"
        )
        try:
            return subprocess.run(
                ["powershell.exe", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command", launcher_script],
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                check=False,
                timeout=90,
                creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
            )
        except FileNotFoundError as exc:
            raise RuntimeError("Не удалось запросить права администратора: не найден PowerShell.") from exc
        except subprocess.TimeoutExpired as exc:
            raise RuntimeError("Windows Firewall не ответил вовремя после запроса прав администратора.") from exc

    @classmethod
    def _run_netsh(cls, arguments: list[str]) -> None:
        try:
            result = subprocess.run(["netsh", *arguments], capture_output=True, text=True, encoding="utf-8", errors="replace", check=False, timeout=15)
        except FileNotFoundError as exc:
            raise RuntimeError("Windows Firewall недоступен: не найдена команда netsh.") from exc
        except subprocess.TimeoutExpired as exc:
            raise RuntimeError("Windows Firewall не ответил вовремя.") from exc
        if result.returncode == 0:
            return
        output = cls._command_output(result)
        if cls._requires_elevation(output):
            elevated = cls._run_elevated_netsh(arguments)
            if elevated.returncode == 0:
                return
            elevated_output = cls._command_output(elevated)
            if cls._uac_was_cancelled(elevated.returncode, elevated_output):
                raise PermissionError("Изменение Firewall отменено в окне контроля учётных записей Windows.")
            if "0xc0000142" in elevated_output.lower():
                raise RuntimeError("Windows не смогла запустить процесс с правами администратора (0xC0000142). Правило Firewall не изменено.")
            raise RuntimeError(elevated_output or "Не удалось изменить правило Windows Firewall после запроса прав администратора.")
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

    @staticmethod
    def _signature(record: dict[str, Any]) -> tuple[str, ...]:
        """Fields that make a Firewall rule meaningfully identical."""
        return tuple(str(record.get(key) or "").strip().lower() for key in (
            "program", "action", "direction", "protocol", "local_port", "remote_port", "remote_ip", "profile",
        ))

    def _record(self, values: dict[str, Any], rule_id: str, system_name: str) -> dict[str, Any]:
        """Validate all user input before it can reach netsh."""
        program = Path(str(values.get("program") or "").strip())
        if not program.is_file() or program.suffix.lower() != ".exe":
            raise ValueError("Укажите существующий .exe-файл программы.")
        action = str(values.get("action") or "block").lower()
        direction = str(values.get("direction") or "outbound").lower()
        protocol = str(values.get("protocol") or "any").lower()
        profile = str(values.get("profile") or "any").lower()
        if action not in ACTIONS or direction not in DIRECTIONS or protocol not in PROTOCOLS or profile not in PROFILES:
            raise ValueError("Недопустимые параметры правила Firewall.")
        return {
            "id": rule_id,
            "system_name": system_name,
            "label": self._label(values.get("label") or program.stem),
            "program": str(program),
            "action": action,
            "direction": direction,
            "protocol": protocol,
            "local_port": self._ports(values.get("local_port", "")),
            "remote_port": self._ports(values.get("remote_port", "")),
            "remote_ip": self._remote_addresses(values.get("remote_ip", "")),
            "profile": profile,
            "enabled": True,
        }

    def _add_rule(self, record: dict[str, Any]) -> None:
        self._run_netsh([
            "advfirewall", "firewall", "add", "rule", f"name={record['system_name']}", f"dir={DIRECTIONS[record['direction']]}",
            f"action={record['action']}", f"program={record['program']}", f"enable={'yes' if record.get('enabled', True) else 'no'}", f"profile={record['profile']}",
            f"protocol={record['protocol'].upper()}", f"localport={record['local_port']}", f"remoteport={record.get('remote_port', 'any')}", f"remoteip={record['remote_ip']}",
        ])

    def _set_rule(self, record: dict[str, Any]) -> None:
        """Update an owned rule in place so an invalid edit cannot remove it."""
        self._run_netsh([
            "advfirewall", "firewall", "set", "rule", f"name={record['system_name']}", "new",
            f"dir={DIRECTIONS[record['direction']]}", f"action={record['action']}", f"program={record['program']}",
            f"enable={'yes' if record.get('enabled', True) else 'no'}", f"profile={record['profile']}",
            f"protocol={record['protocol'].upper()}", f"localport={record['local_port']}", f"remoteport={record.get('remote_port', 'any')}", f"remoteip={record['remote_ip']}",
        ])

    def _delete_system_rule(self, record: dict[str, Any]) -> None:
        self._run_netsh(["advfirewall", "firewall", "delete", "rule", f"name={record['system_name']}"])

    def _save_or_rollback(self, rules: dict[str, dict[str, Any]], rollback: Any, operation: str) -> None:
        """Keep V.E.R.A.'s local index and the Windows rule in lockstep."""
        try:
            self._save(rules)
        except (OSError, TypeError, ValueError) as exc:
            try:
                rollback()
            except (OSError, PermissionError, RuntimeError) as rollback_exc:
                raise RuntimeError(
                    f"Не удалось сохранить состояние после операции «{operation}», а откат правила Windows Firewall также не удался: {rollback_exc}"
                ) from exc
            raise RuntimeError(f"Не удалось сохранить состояние после операции «{operation}». Изменение правила Windows Firewall отменено.") from exc

    def create(self, values: dict[str, Any]) -> dict[str, Any]:
        rule_id = uuid.uuid4().hex[:12]
        record = self._record(values, rule_id, f"{RULE_PREFIX} #{rule_id}")
        rules = self._load()
        if any(self._signature(existing) == self._signature(record) for existing in rules.values()):
            raise ValueError("Такое правило V.E.R.A. Firewall уже существует.")
        self._add_rule(record)
        updated_rules = {**rules, rule_id: record}
        self._save_or_rollback(updated_rules, lambda: self._delete_system_rule(record), "создание")
        return record

    def update(self, rule_id: str, values: dict[str, Any]) -> dict[str, Any]:
        """Replace one known V.E.R.A. rule after the same strict validation."""
        rules = self._load()
        existing = rules.get(str(rule_id))
        if not existing:
            raise ValueError("Правило Firewall не найдено.")
        record = self._record(values, str(rule_id), str(existing["system_name"]))
        # Editing a disabled rule must not silently enable it again.
        record["enabled"] = bool(existing.get("enabled", True))
        if any(key != str(rule_id) and self._signature(other) == self._signature(record) for key, other in rules.items()):
            raise ValueError("Такое правило V.E.R.A. Firewall уже существует.")
        self._set_rule(record)
        updated_rules = {**rules, str(rule_id): record}
        self._save_or_rollback(updated_rules, lambda: self._set_rule(existing), "обновление")
        return record

    def toggle(self, rule_id: str) -> dict[str, Any]:
        rules = self._load(); record = rules.get(str(rule_id))
        if not record:
            raise ValueError("Правило Firewall не найдено.")
        updated = {**record, "enabled": not bool(record.get("enabled"))}
        self._set_rule(updated)
        updated_rules = {**rules, str(rule_id): updated}
        self._save_or_rollback(updated_rules, lambda: self._set_rule(record), "изменение состояния")
        return updated

    def delete(self, rule_id: str) -> bool:
        rules = self._load(); record = rules.get(str(rule_id))
        if not record:
            raise ValueError("Правило Firewall не найдено.")
        self._delete_system_rule(record)
        updated_rules = {key: value for key, value in rules.items() if key != str(rule_id)}
        self._save_or_rollback(updated_rules, lambda: self._add_rule(record), "удаление")
        return True
