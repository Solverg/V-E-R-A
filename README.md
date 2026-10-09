# V.E.R.A.

**Verified Executive & Reliability Assistant** is a Windows desktop application
for inspecting running processes, checking their digital signatures, and
managing process, firewall, network, and startup controls.

> V.E.R.A. helps inspect and manage a Windows system; it is not an antivirus,
> an endpoint-detection product, or a substitute for backups and Windows
> security updates.

## What it does

- Lists live Windows processes, including PID, CPU, memory use, executable
  path, locally checked Authenticode status, and blocking state.
- Creates path-aware block rules. Permanent rules are re-applied while
  monitoring is enabled; **Kill-on-Launch** rules run only during the first
  enabled monitoring cycle after V.E.R.A. starts.
- Provides Network Radar: process-owned connections, risk classification,
  filtering, and public-IP metadata.
- Manages V.E.R.A.-owned Windows Firewall rules for a program, direction,
  protocol, local ports, remote IP addresses, and network profile.
- Lists and pauses/resumes startup entries from Run keys, Startup folders, and
  LogonTrigger tasks.
- Optionally connects to Gemini or Groq for chat and cached process
  descriptions. Provider keys are stored with Windows DPAPI.
- Supports app autostart and system-tray operation. Closing the main window
  hides V.E.R.A. to the notification area; use the tray menu's **Open V.E.R.A.**
  command to show it again, or **Exit** to stop it completely.

The interface copy is in Russian. See [the copy guide](docs/localization.md)
for terminology rules.

## Important behavior and data handling

- V.E.R.A. writes its local data to `%USERPROFILE%\.vera\`. On first launch,
  it can copy known legacy `blocked.json` and `settings.json` files from
  `.kristina_helper`; see [migration parity](docs/migration-parity.md).
- Changing Firewall rules and some startup entries requires Windows elevation.
  Without it, Windows can return **Access Denied**.
- Digital-signature status is evidence about a file's signature, not a malware
  verdict. Review a file's source before allowing or blocking it.
- Network Radar's external-IP lookup contacts public IP-information services.
  When an AI provider is enabled, chat text and the requested process context
  are sent to that provider. For automatic process descriptions, the local
  Windows user name in a path is redacted before the provider request.
- From version 0.3.8 onward, the installed app can check signed updates from
  GitHub Releases. It asks for confirmation before downloading and installing
  an update.

## Architecture

```text
Tauri UI (HTML/CSS/JavaScript)
        │
Tauri IPC
        │
Python backend sidecar (processes, signatures, rules, network, firewall)
        │
Windows APIs and V.E.R.A. user data
```

## Development

The repository includes an embedded Python 3.13 runtime at
`.python\runtime\python.exe`. Node.js 22+ and Rust stable with the MSVC
toolchain are also required.

```powershell
# Install the sidecar's packaging dependencies into the embedded runtime.
& .\.python\runtime\python.exe -m pip install -r requirements-build.txt

# Build the Python sidecar expected by Tauri.
.\scripts\build-tauri-backend.ps1

# Run the desktop client.
Set-Location desktop
npm ci
npm run dev
```

`npm run frontend:dev` starts a browser-only preview with sample data.
`npm run dev` starts the Tauri desktop application and calls the local sidecar.

To use another Python runtime, pass its repository-relative path to the build
script, for example:

```powershell
.\scripts\build-tauri-backend.ps1 -Python ".venv\Scripts\python.exe"
```

## Verify and build

```powershell
# Backend tests, from the repository root.
& .\.python\runtime\python.exe -m unittest tests.test_backend_service

# Frontend production build, from desktop/.
npm run build

# Create the NSIS installer, from desktop/.
npm run tauri -- build
```

The generated Python sidecar is placed in
`desktop/src-tauri/binaries/vera-backend-x86_64-pc-windows-msvc/`.

Before publishing an installer, follow the
[release guide](docs/release-guide.md). It includes validation steps and the
current release blockers.

## Project structure

```text
backend/                 Python sidecar and Windows integrations
desktop/                 Tauri frontend and Rust shell
docs/                    Product, migration, and release documentation
scripts/build-tauri-backend.ps1
tests/test_backend_service.py
requirements.txt         Backend runtime dependency
requirements-build.txt   Packaging dependency set
```

## License

V.E.R.A. is **source-available**, not open-source under an OSI-approved
license. It is licensed under the
[PolyForm Noncommercial License 1.0.0](LICENSE.md): noncommercial use,
modification, and sharing are permitted under its terms. Commercial use needs a
separate written agreement from the copyright holder.

The SPDX identifier, package metadata, and installer configuration use
`PolyForm-Noncommercial-1.0.0` so the license is carried into release bundles.
