# V.E.R.A. release guide

V.E.R.A. publishes Windows releases through GitHub Releases. Starting with
`0.3.8`, the installed app uses the Tauri Updater plugin and accepts only an
artifact signed by the configured updater public key.

## One-time repository setup

1. Create the public GitHub repository `Solverg/V-E-R-A` and push this project
   to its default branch.
2. In the repository's Actions secrets, add `TAURI_SIGNING_PRIVATE_KEY` with
   the full content of the locally generated `.keys/vera-updater.key` file.
   Never commit, paste into an issue, or otherwise publish that file.
3. Keep an encrypted offline backup of that private key. If it is lost, future
   versions cannot update installations signed by the current public key.
4. Enable GitHub Actions workflows and grant the workflow `contents: write`
   permission. The workflow file is `.github/workflows/publish.yml`.

The updater endpoint is the release asset URL
`https://github.com/Solverg/V-E-R-A/releases/latest/download/latest.json`.
GitHub's latest-release route excludes drafts and prereleases, so publish the
release only after its assets and notes have been reviewed.

## Publish a release

1. Choose a semantic version and update it consistently in:
   - `desktop/package.json`
   - `desktop/package-lock.json`
   - `desktop/src-tauri/Cargo.toml`
   - `desktop/src-tauri/tauri.conf.json`
   - the About panel in `desktop/src/main.js`
2. Add user-facing notes based only on verified changes.
3. Commit the release changes and push a matching tag, for example `v0.4.0`.
4. GitHub Actions builds the Python sidecar, creates a signed NSIS updater
   artifact and its signature, then opens a draft release with `latest.json`.
5. Test the draft's installer on a clean Windows account. Confirm that the
   app starts, the backend connects, and **Settings → Check for updates**
   behaves correctly.
6. Publish the GitHub release. Only then does it become the update offered to
   existing installations.

## Local validation

Run from the repository root:

```powershell
& .\.python\runtime\python.exe -m unittest tests.test_backend_service
Set-Location desktop
npm ci
npm run build
npm run tauri -- build --no-bundle
```

To make a local signed installer, set `TAURI_SIGNING_PRIVATE_KEY` to the path
or content of the private key for the current PowerShell session, then run the
normal Tauri build. Do not store that environment value in a tracked file.

## Remaining release requirements

- `0.3.8` is the first updater-enabled release; an installation of `0.3.7`
  cannot update itself and should be replaced with the new installer once.
- A complete third-party-notice inventory still needs review before public
  binary distribution.
- The Tauri updater signature protects downloaded update artifacts, but a
  Windows code-signing certificate and timestamp are still recommended for the
  installer and executable reputation in Windows.

## Publish record

For every release retain the tag, installer digest, test-account result, and
exact source revision. Publish the SHA-256 digest beside the installer.
