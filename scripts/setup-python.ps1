$ErrorActionPreference = "Stop"

$PythonVersion = "3.13.13"
$PythonTag = "313"
$ArchiveName = "python-$PythonVersion-embed-amd64.zip"
$PythonUrl = "https://www.python.org/ftp/python/$PythonVersion/$ArchiveName"
$GetPipUrl = "https://bootstrap.pypa.io/get-pip.py"

$RepoRoot = Resolve-Path (Join-Path $PSScriptRoot "..")
$PythonDir = Join-Path $RepoRoot ".python"
$RuntimeDir = Join-Path $PythonDir "runtime"
$ArchivePath = Join-Path $PythonDir $ArchiveName
$GetPipPath = Join-Path $PythonDir "get-pip.py"
$PythonExe = Join-Path $RuntimeDir "python.exe"
$PthFile = Join-Path $RuntimeDir "python$PythonTag._pth"

New-Item -ItemType Directory -Force -Path $PythonDir | Out-Null

if (-not (Test-Path -LiteralPath $ArchivePath)) {
    Invoke-WebRequest -Uri $PythonUrl -OutFile $ArchivePath
}

Expand-Archive -LiteralPath $ArchivePath -DestinationPath $RuntimeDir -Force

$signature = Get-AuthenticodeSignature -LiteralPath $PythonExe
if ($signature.Status -ne "Valid" -or $signature.SignerCertificate.Subject -notlike "*Python Software Foundation*") {
    throw "Python signature verification failed: $($signature.Status) $($signature.SignerCertificate.Subject)"
}

$pth = Get-Content -LiteralPath $PthFile
$pth = $pth | ForEach-Object {
    if ($_ -eq "#import site") {
        "import site"
    }
    else {
        $_
    }
}

if ($pth -notcontains "..\..") {
    $newPth = @()
    $inserted = $false
    foreach ($line in $pth) {
        if (-not $inserted -and $line -eq "") {
            $newPth += "..\.."
            $inserted = $true
        }
        $newPth += $line
    }
    if (-not $inserted) {
        $newPth += "..\.."
    }
    $pth = $newPth
}

Set-Content -LiteralPath $PthFile -Value $pth -Encoding ASCII

Invoke-WebRequest -Uri $GetPipUrl -OutFile $GetPipPath
& $PythonExe $GetPipPath --no-warn-script-location
& $PythonExe -m pip install -r (Join-Path $RepoRoot "requirements.txt")

& $PythonExe --version
