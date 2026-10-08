# V.E.R.A. migration parity

Historical parity audit of the legacy Kristina Helper implementation. The
legacy source path is deliberately not part of release documentation.

| Legacy file | Function | V.E.R.A. implementation | API action | Test | Status |
|---|---|---|---|---|---|
| `app/process_manager.py`, `blocked_panel.py` | process inventory and blocks | `backend/service.py`, Rust timer, Processes/Blocks screens | `processes.list`, `rules.*`, `processes.enforce` | `test_backend_service.py` | implemented |
| `app/network_monitor.py`, `network_radar_panel.py` | network inventory/risk/public IP | `backend/network.py`, Network Radar | `network.list`, `network.public_ip` | classification/risk tests | implemented |
| `app/startup_manager.py`, `startup_panel.py` | Run keys, folders, tasks, pause/resume | `backend/startup.py`, Startup screen | `startup.list`, `startup.toggle` | Task XML test | implemented |
| `app/autostart.py` | app startup registration | `backend/startup.py`, Settings | `app_autostart.get/set` | backend action coverage | implemented |
| `app/secure_storage.py`, `settings.py`, `redaction.py` | DPAPI keys, settings, redaction | `secure_storage.py`, `settings_store.py`, `redaction.py` | `settings.get/set` | secret omission test | implemented |
| `app/ai_chat.py`, `processes_panel.py` | Gemini/Groq chat and explanation | `backend/assistant.py`, Assistant screen | `assistant.chat`, `process.describe` | path-redaction test | implemented |
| `app/tray.py` | tray lifecycle | `desktop/src-tauri/src/lib.rs` | Tauri commands | build | implemented |
| `app/updater.py` | releases check/install | Tauri Updater plugin, signed GitHub Releases artifacts | `@tauri-apps/plugin-updater` | release workflow and clean-account smoke test | implemented for V.E.R.A. 0.3.8+ |

## Monitoring design

The Rust Tauri shell owns the scheduler. It runs a short-lived sidecar request only at the configured 1–60 second interval and calls `processes.enforce`; this avoids a Python daemon and keeps every Windows action in the sidecar. `kill_on_launch` rules are sent only in the first enabled monitor cycle; `permanent` rules run every cycle. Process PID, name, and executable path are checked again directly before termination.

## Update delivery

V.E.R.A. 0.3.8 and later use the Tauri updater. The app verifies the signed
NSIS artifact published in GitHub Releases before installation and asks the
user for confirmation. The original 0.3.7 installer did not include this
mechanism and must be replaced by the first 0.3.8 release.
