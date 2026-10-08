# V.E.R.A. Tauri desktop shell

This is the V.E.R.A. desktop client. It uses a Tauri window and a web
frontend, while `backend/service.py` provides headless process-management
operations. The top-level [README](../README.md) documents product behavior,
data handling, and the source-available license; use the
[release guide](../docs/release-guide.md) before publishing an installer.

## Architecture

```text
Tauri window (HTML/CSS/JS)
        │ Tauri shell sidecar IPC
Python backend (processes, block rules)
        │
Windows APIs and V.E.R.A. user data
```

The distributable is intentionally a normal application folder/installer: the
Tauri executable, WebView runtime integration, and `vera-backend` sidecar are
separate runtime assets.

## Run the client

```powershell
cd desktop
npm ci
npm run dev
```

The browser preview uses safe sample data. In a Tauri build, the same UI calls
the Python sidecar and lists real local processes.

## Build prerequisites

- Node.js 22+
- Rust stable with the MSVC toolchain
- Python runtime with `requirements-build.txt` installed

Prepare the sidecar after Rust is installed:

```powershell
.\scripts\build-tauri-backend.ps1
cd desktop
npm run tauri -- build
```

Tauri expects its sidecar executable at
`desktop/src-tauri/binaries/vera-backend-x86_64-pc-windows-msvc/vera-backend-x86_64-pc-windows-msvc.exe`.

The bundle configuration includes `../../LICENSE.md`, which contains the
PolyForm Noncommercial License 1.0.0 and the project copyright notice. Do not
replace it with a different license text without reviewing the release policy.
