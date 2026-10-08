param(
    [string]$Python = ".\.python\runtime\python.exe",
    [string]$TargetTriple = "x86_64-pc-windows-msvc"
)

$ErrorActionPreference = "Stop"
$RepoRoot = Resolve-Path (Join-Path $PSScriptRoot "..")
$PythonPath = if ([System.IO.Path]::IsPathRooted($Python)) { $Python } else { Join-Path $RepoRoot $Python }
$SidecarName = "vera-backend-$TargetTriple"
$BuildRoot = Join-Path $RepoRoot "build\tauri-backend"
$DistDir = Join-Path $BuildRoot "dist"
$WorkDir = Join-Path $BuildRoot "work"
$OutputRoot = Join-Path $RepoRoot "desktop\src-tauri\binaries"
$OutputDir = Join-Path $OutputRoot $SidecarName

if (-not (Test-Path -LiteralPath $PythonPath)) {
    throw "Python runtime not found: $PythonPath"
}

Push-Location $RepoRoot
try {
    # Keep the Python runtime next to the executable.  A Tauri sidecar must not
    # depend on a temporary one-file PyInstaller extraction directory.
    & $PythonPath -m PyInstaller --noconfirm --clean --onedir --contents-directory _internal `
        --name $SidecarName --distpath $DistDir --workpath $WorkDir backend\service.py
    if ($LASTEXITCODE -ne 0) { throw "PyInstaller backend build failed." }

    $BuiltSidecarDir = Join-Path $DistDir $SidecarName
    if (-not (Test-Path -LiteralPath $BuiltSidecarDir)) {
        throw "PyInstaller output not found: $BuiltSidecarDir"
    }

    New-Item -ItemType Directory -Force -Path $OutputRoot | Out-Null
    if (Test-Path -LiteralPath $OutputDir) {
        Remove-Item -Recurse -Force -LiteralPath $OutputDir
    }
    Copy-Item -Recurse -Force -LiteralPath $BuiltSidecarDir -Destination $OutputRoot
}
finally {
    Pop-Location
}
