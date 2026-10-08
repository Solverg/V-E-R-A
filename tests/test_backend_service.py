import tempfile
import unittest
import json
from types import SimpleNamespace
from unittest.mock import patch
from pathlib import Path
from backend.network import classify_address, calculate_risk, list_connections, public_ip
from backend.assistant import _describe_with_provider, redact_path
from backend.startup import StartupManager

from backend.service import BackendService, BlockRule
from backend.firewall import FirewallManager
from backend.windows_icons import MAX_ICON_BATCH, _png_rgba, _load_cached_icon, _store_cached_icon, process_icons
from backend.signature_verifier import STATUS_VERIFIED, SignatureVerification


class BackendServiceTests(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.service = BackendService(Path(self.temp_dir.name))

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_health_request(self):
        response = self.service.handle({"action": "health"})
        self.assertTrue(response["ok"])
        self.assertEqual(response["data"]["service"], "vera-backend")

    def test_rule_lifecycle(self):
        created = self.service.handle({"action": "rules.upsert", "name": "demo.exe"})
        self.assertTrue(created["ok"])
        self.assertTrue(created["data"]["enabled"])

        toggled = self.service.handle({"action": "rules.toggle", "name": "demo.exe"})
        self.assertFalse(toggled["data"]["enabled"])

        listed = self.service.handle({"action": "rules.list"})
        self.assertEqual(len(listed["data"]), 1)
        self.assertTrue(self.service.handle({"action": "rules.delete", "name": "demo.exe"})["data"])

    def test_rule_list_keeps_the_cached_description_for_the_rules_screen(self):
        self.service.upsert_rule("demo.exe", exe_path=r"C:\Apps\demo.exe")
        (Path(self.temp_dir.name) / "descriptions.json").write_text(
            json.dumps({"demo.exe|c:\\apps\\demo.exe": {"description": "Тестовое описание.", "status": "verified"}}),
            encoding="utf-8",
        )

        listed = self.service.handle({"action": "rules.list"})["data"]
        self.assertEqual(listed[0]["description"], "Тестовое описание.")
        self.assertEqual(listed[0]["description_status"], "verified")

    def test_process_list_exposes_both_block_modes(self):
        self.service.upsert_rule("permanent.exe", mode="permanent")
        self.service.upsert_rule("launch.exe", mode="kill_on_launch")
        processes = [
            SimpleNamespace(info={"pid": 101, "name": "permanent.exe", "exe": "", "status": "running", "cpu_percent": 0, "memory_info": None}),
            SimpleNamespace(info={"pid": 102, "name": "launch.exe", "exe": "", "status": "running", "cpu_percent": 0, "memory_info": None}),
        ]

        with patch("backend.service.psutil.process_iter", return_value=processes):
            listed = self.service.list_processes()

        modes_by_name = {process["name"]: process["block_mode"] for process in listed}
        self.assertEqual(modes_by_name, {"permanent.exe": "permanent", "launch.exe": "kill_on_launch"})
        self.assertTrue(all(process["block_rule_exe_path"] == "" for process in listed))

    def test_settings_never_returns_secrets(self):
        result = self.service.handle({"action": "settings.set", "values": {"scan_interval_sec": 99}})
        self.assertEqual(result["data"]["scan_interval_sec"], 60)
        self.assertNotIn("gemini_api_key", self.service.handle({"action": "settings.get"})["data"])

    def test_process_snapshot_collects_processes_once(self):
        processes = [{"pid": 10, "name": "demo.exe", "is_blocked": True}]
        with patch.object(self.service, "list_processes", return_value=processes) as list_processes:
            response = self.service.handle({"action": "processes.snapshot"})

        self.assertTrue(response["ok"])
        self.assertEqual(response["data"]["processes"], processes)
        self.assertEqual(response["data"]["statistics"]["total_processes"], 1)
        self.assertEqual(response["data"]["statistics"]["active_blocked_processes"], 1)
        list_processes.assert_called_once_with()

    def test_visible_process_signature_batch_is_limited_and_returns_statuses(self):
        processes = [{"pid": index, "exe": f"C:\\Apps\\{index}.exe"} for index in range(40)]
        signature = SignatureVerification(STATUS_VERIFIED, True)
        with patch("backend.service.verify_executable_signature", return_value=signature) as verify:
            response = self.service.handle({"action": "processes.verify_signatures", "processes": processes})

        self.assertTrue(response["ok"])
        self.assertEqual(len(response["data"]), 32)
        self.assertTrue(all(row["security_status"] == "verified" for row in response["data"]))
        self.assertEqual(verify.call_count, 32)

    def test_visible_process_icon_batch_is_bounded_and_deduplicated(self):
        processes = [{"pid": index, "exe": rf"C:\\Apps\\{index}.exe"} for index in range(MAX_ICON_BATCH + 4)]
        processes.insert(1, {"pid": 999, "exe": processes[0]["exe"]})
        with patch("backend.windows_icons._safe_executable_path", side_effect=lambda path: path), patch("backend.windows_icons._file_marker", return_value={"size": 1, "mtime_ns": 1}), patch("backend.windows_icons.executable_icon_data_url", return_value="data:image/png;base64,test") as icon:
            result = process_icons(processes)

        self.assertEqual(len(result), MAX_ICON_BATCH)
        self.assertEqual(icon.call_count, MAX_ICON_BATCH)
        self.assertEqual(result[0]["pid"], 0)

    def test_icon_png_encoder_writes_png_signature(self):
        image = _png_rgba(1, 1, bytes((10, 20, 30, 255)))
        self.assertEqual(image[:8], b"\x89PNG\r\n\x1a\n")

    def test_icon_cache_persists_and_rejects_changed_executables(self):
        cache_dir = Path(self.temp_dir.name) / "icon-cache"
        executable = r"C:\\Apps\\demo.exe"
        marker = {"size": 12, "mtime_ns": 34}
        _store_cached_icon(cache_dir, executable, marker, "data:image/png;base64,test")

        self.assertEqual(_load_cached_icon(cache_dir, executable, marker), "data:image/png;base64,test")
        self.assertIsNone(_load_cached_icon(cache_dir, executable, {"size": 13, "mtime_ns": 34}))

    def test_enforcement_loads_rules_once_and_saves_all_kill_counts_together(self):
        rule = BlockRule(name="demo.exe")
        rules = {self.service.rule_key(rule.name): rule}
        processes = [
            SimpleNamespace(info={"pid": 101, "name": "demo.exe", "exe": r"C:\\Apps\\demo.exe"}),
            SimpleNamespace(info={"pid": 102, "name": "demo.exe", "exe": r"C:\\Apps\\demo.exe"}),
        ]
        with patch("backend.service.psutil.process_iter", return_value=processes), patch.object(self.service, "_load_rules", return_value=rules) as load_rules, patch.object(self.service, "_save_rules") as save_rules, patch.object(self.service, "terminate_process", return_value=True) as terminate, patch.object(self.service, "list_processes") as list_processes:
            result = self.service.enforce_processes()

        self.assertEqual(result, {"terminated": 2, "session_terminated": 2})
        self.assertEqual(rule.kill_count, 2)
        load_rules.assert_called_once_with()
        save_rules.assert_called_once_with(rules)
        self.assertEqual(terminate.call_count, 2)
        list_processes.assert_not_called()

    def test_network_address_classification_and_risk(self):
        self.assertEqual(classify_address(""), "empty")
        self.assertEqual(classify_address("127.0.0.1"), "loopback")
        self.assertEqual(classify_address("192.168.1.5"), "private")
        self.assertEqual(classify_address("8.8.8.8"), "public")
        self.assertEqual(calculate_risk("unknown", "", "public", "ESTABLISHED"), "attention")
        self.assertEqual(calculate_risk("app.exe", r"C:\Users\u\AppData\Local\a.exe", "public", "ESTABLISHED"), "attention")
        self.assertEqual(calculate_risk("app.exe", r"C:\Program Files\a.exe", "public", "ESTABLISHED"), "medium")

    def test_public_ip_uses_fallback_and_does_not_fail_the_radar(self):
        with patch("backend.network._fetch", side_effect=["not-json", "not-json", "not-json", "not-json", "8.8.8.8\n"]):
            result = public_ip()
        self.assertEqual(result["ip"], "8.8.8.8")
        self.assertNotIn("error", result)

    def test_public_ip_returns_degraded_response_when_services_are_unavailable(self):
        with patch("backend.network._fetch", side_effect=OSError("offline")):
            result = public_ip()
        self.assertEqual(result["ip"], "")
        self.assertIn("error", result)

    def test_network_uses_netstat_when_psutil_access_is_denied(self):
        netstat = """\n  TCP    10.0.0.2:51515    8.8.8.8:443    ESTABLISHED    123\n  UDP    0.0.0.0:5353     *:*                         456\n"""
        with patch("backend.network.psutil.net_connections", side_effect=__import__("psutil").AccessDenied()), patch("backend.network.subprocess.run") as run:
            run.return_value.stdout = netstat
            result = list_connections()
        self.assertEqual(len(result), 2)
        self.assertEqual(result[0]["remote_address"], "8.8.8.8")
        self.assertEqual(result[0]["status"], "ESTABLISHED")

    def test_firewall_rule_lifecycle_only_tracks_vera_rules(self):
        executable = Path(self.temp_dir.name) / "demo.exe"
        executable.touch()
        manager = FirewallManager(Path(self.temp_dir.name))
        values = {"label": "Block demo", "program": str(executable), "action": "block", "direction": "outbound", "protocol": "tcp", "local_port": "443", "remote_ip": "8.8.8.8", "profile": "private"}
        with patch.object(FirewallManager, "_run_netsh") as netsh:
            created = manager.create(values)
            self.assertTrue(created["system_name"].startswith("V.E.R.A. Firewall"))
            self.assertEqual(manager.list()[0]["program"], str(executable))
            toggled = manager.toggle(created["id"])
            self.assertFalse(toggled["enabled"])
            self.assertTrue(manager.delete(created["id"]))
        self.assertEqual(netsh.call_count, 3)
        self.assertEqual(manager.list(), [])

    def test_firewall_rejects_unsafe_rule_values(self):
        manager = FirewallManager(Path(self.temp_dir.name))
        with self.assertRaises(ValueError):
            manager.create({"label": "Bad", "program": "C:\\not-an-exe.txt"})

    def test_redacts_user_name_from_path(self):
        self.assertEqual(redact_path(r"C:\Users\Alice\AppData\app.exe"), r"C:\Users\<user>\AppData\app.exe")

    def test_process_descriptions_are_cached_locally_and_can_be_refreshed(self):
        description = {"description": "Обеспечивает тестовую функцию.", "status": "verified"}
        with patch("backend.assistant._describe_with_provider", return_value=json.dumps(description, ensure_ascii=False)) as request:
            first = self.service.handle({"action": "process.describe", "name": "demo.exe", "exe_path": r"C:\Apps\demo.exe"})
            second = self.service.handle({"action": "process.describe", "name": "demo.exe", "exe_path": r"C:\Apps\demo.exe"})
            refreshed = self.service.handle({"action": "process.describe", "name": "demo.exe", "exe_path": r"C:\Apps\demo.exe", "force": True})

        self.assertEqual(first["data"], description)
        self.assertEqual(second["data"], description)
        self.assertEqual(refreshed["data"], description)
        self.assertEqual(request.call_count, 2)
        cache = json.loads((Path(self.temp_dir.name) / "descriptions.json").read_text(encoding="utf-8"))
        self.assertEqual(cache["demo.exe"]["description"], description["description"])

    def test_description_request_uses_gemini_json_schema(self):
        settings = SimpleNamespace(
            public=lambda: {"provider": "gemini", "gemini_model": "gemini-test"},
            secret=lambda key: "test-key" if key == "gemini_api_key" else "",
        )
        response = {"candidates": [{"content": {"parts": [{"text": '{"description":"Тест.","status":"unknown"}'}]}}]}
        with patch("backend.assistant._request", return_value=response) as request:
            _describe_with_provider(settings, "Опиши тестовый процесс")

        body = request.call_args.args[1]
        config = body["generationConfig"]
        self.assertEqual(config["responseMimeType"], "application/json")
        self.assertEqual(config["responseSchema"]["required"], ["description", "status"])
        self.assertEqual(config["temperature"], 0.1)

    def test_legacy_description_cache_is_migrated(self):
        legacy_dir = Path(self.temp_dir.name) / "legacy"
        current_dir = Path(self.temp_dir.name) / "current"
        legacy_dir.mkdir()
        legacy_content = {"demo.exe": {"description": "Старое описание.", "status": "unknown"}}
        (legacy_dir / "descriptions.json").write_text(json.dumps(legacy_content), encoding="utf-8")

        with patch("backend.service.DEFAULT_DATA_DIR", current_dir), patch("backend.service.LEGACY_DATA_DIR", legacy_dir), patch("backend.service.resolve_data_dir", return_value=current_dir):
            BackendService()

        migrated = json.loads((current_dir / "descriptions.json").read_text(encoding="utf-8"))
        self.assertEqual(migrated, legacy_content)

    def test_parses_logon_task_xml(self):
        xml = '''<Task xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task"><RegistrationInfo><URI>\\Demo</URI></RegistrationInfo><Triggers><LogonTrigger/></Triggers><Settings><Enabled>true</Enabled></Settings><Actions><Exec><Command>C:\\demo.exe</Command></Exec></Actions></Task>'''
        rows = StartupManager.parse_schtasks_xml(xml)
        self.assertEqual(rows[0].name, "Demo")
        self.assertEqual(rows[0].status, "active")

    def test_startup_tasks_keep_legacy_admin_requirement(self):
        xml = '''<Task xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task"><RegistrationInfo><URI>\\Demo</URI></RegistrationInfo><Triggers><LogonTrigger/></Triggers><Settings><Enabled>true</Enabled></Settings><Actions><Exec><Command>C:\\demo.exe</Command></Exec></Actions></Task>'''
        with patch.object(StartupManager, "is_admin", return_value=False):
            rows = StartupManager.parse_schtasks_xml(xml)

        self.assertTrue(rows[0].needs_admin)
        with patch.object(StartupManager, "is_admin", return_value=False):
            with self.assertRaises(PermissionError):
                StartupManager.toggle({"source": "TASK_SCHEDULER", "status": "active", "raw_key": "\\Demo"})

    def test_startup_shortcut_target_is_resolved_with_a_safe_powershell_argument(self):
        with patch("backend.startup.subprocess.run") as run:
            run.return_value = SimpleNamespace(stdout="C:\\Apps\\demo.exe\n")
            target = StartupManager._resolve_shortcut(r"C:\Startup\demo.lnk")

        self.assertEqual(target, r"C:\Apps\demo.exe")
        self.assertIn("-NoProfile", run.call_args.args[0])
