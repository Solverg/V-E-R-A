$ErrorActionPreference = "Stop"

$RepoRoot = Resolve-Path (Join-Path $PSScriptRoot "..")

function Resolve-ProjectPython {
    $candidates = @(
        (Join-Path $RepoRoot ".python\runtime\python.exe"),
        (Join-Path $RepoRoot ".venv\Scripts\python.exe")
    )

    foreach ($candidate in $candidates) {
        if (Test-Path -LiteralPath $candidate) {
            return $candidate
        }
    }

    $systemPython = Get-Command python -ErrorAction SilentlyContinue
    if ($systemPython) {
        return $systemPython.Source
    }

    throw "Python was not found. Run scripts\setup-python.ps1, create .venv, or install Python 3.13+ on PATH."
}

$Python = Resolve-ProjectPython
Write-Host "Using Python: $Python"

Push-Location $RepoRoot
try {
    & $Python --version
    & $Python -m pip check
    Write-Host "Running V.E.R.A. backend tests..."
    & $Python -m unittest tests.test_backend_service
    & $Python -m compileall -q backend
    & $Python -c "import backend.service, backend.signature_verifier; print('imports:ok')"
}
finally {
    Pop-Location
}
