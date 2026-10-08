$ErrorActionPreference = "SilentlyContinue"

$vswhere = "C:\Program Files (x86)\Microsoft Visual Studio\Installer\vswhere.exe"
$linkPattern = "C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Tools\MSVC\*\bin\Hostx64\x64\link.exe"

while ($true) {
    Clear-Host
Write-Host "V.E.R.A. — установка MSVC Build Tools" -ForegroundColor Cyan
    Write-Host ("Обновлено: {0}" -f (Get-Date -Format "yyyy-MM-dd HH:mm:ss"))
    Write-Host ""

    $installer = Get-Process vs_setup_bootstrapper, setup -ErrorAction SilentlyContinue
    $linker = Get-ChildItem -Path $linkPattern -ErrorAction SilentlyContinue | Select-Object -First 1
    $installationPath = if (Test-Path $vswhere) {
        & $vswhere -latest -products * -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath
    }

    if ($linker) {
        Write-Host "MSVC linker найден:" -ForegroundColor Green
        Write-Host "  $($linker.FullName)"
    }
    else {
        Write-Host "MSVC linker пока не установлен." -ForegroundColor Yellow
    }

    if ($installationPath) {
        Write-Host "Build Tools зарегистрированы:" -ForegroundColor Green
        Write-Host "  $installationPath"
    }

    Write-Host ""
    if ($installer) {
        Write-Host "Установщик всё ещё работает:" -ForegroundColor Yellow
        $installer | Select-Object ProcessName, Id, CPU, StartTime | Format-Table -AutoSize
    }
    else {
        Write-Host "Процессы установщика завершились." -ForegroundColor Green
    }

    $latestLog = Get-ChildItem -Path $env:TEMP -Filter "dd_setup*.log" -ErrorAction SilentlyContinue |
        Sort-Object LastWriteTime -Descending |
        Select-Object -First 1
    if ($latestLog) {
        Write-Host ""
        Write-Host "Последние строки установочного лога:" -ForegroundColor DarkCyan
        Get-Content -LiteralPath $latestLog.FullName -Tail 8
    }

    if (-not $installer -and $linker -and $installationPath) {
        Write-Host ""
        Write-Host "Готово: можно вернуться в Codex и написать, что установка завершилась." -ForegroundColor Green
        break
    }

    Start-Sleep -Seconds 5
}

Read-Host "Нажмите Enter, чтобы закрыть окно"
