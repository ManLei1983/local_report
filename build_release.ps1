param(
    [string]$PythonExe = "H:\python\3.11.9\python.exe",
    [switch]$IncludeEnv,
    [switch]$IncludeDb,
    [switch]$Zip
)

$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $MyInvocation.MyCommand.Path
$distRoot = Join-Path $root "dist"
$buildRoot = Join-Path $root "build"
$releaseName = "local_report_server"
$releaseDir = Join-Path $distRoot $releaseName

if (Test-Path $releaseDir) { Remove-Item $releaseDir -Recurse -Force }
if (Test-Path (Join-Path $buildRoot $releaseName)) { Remove-Item (Join-Path $buildRoot $releaseName) -Recurse -Force }

& $PythonExe -m PyInstaller `
    --noconfirm `
    --clean `
    --onedir `
    --name $releaseName `
    --collect-all fastapi `
    --collect-all starlette `
    --collect-all uvicorn `
    --collect-all jinja2 `
    --collect-all dotenv `
    --collect-all pydantic `
    --add-data "$root\templates;templates" `
    "$root\app.py"

Copy-Item "$root\.env.example" "$releaseDir\.env.example" -Force
Copy-Item "$root\DEPLOY_GUIDE.md" "$releaseDir\DEPLOY_GUIDE.md" -Force
if ($IncludeEnv -and (Test-Path "$root\.env")) {
    Copy-Item "$root\.env" "$releaseDir\.env" -Force
}
if ($IncludeDb -and (Test-Path "$root\local_report.db")) {
    Copy-Item "$root\local_report.db" "$releaseDir\local_report.db" -Force
}

@"
@echo off
setlocal
cd /d "%~dp0"

set "TARGET_EXE=%~dp0local_report_server.exe"

if not exist "%TARGET_EXE%" (
    echo [ERROR] local_report_server.exe not found
    pause
    exit /b 1
)

powershell.exe -NoProfile -ExecutionPolicy Bypass -Command "$target = [System.IO.Path]::GetFullPath('%TARGET_EXE%'); $items = @(Get-CimInstance Win32_Process -Filter 'name = ''local_report_server.exe''' -ErrorAction SilentlyContinue); if (-not $items) { exit 0 }; $same = @($items | Where-Object { $_.ExecutablePath -and [string]::Equals($_.ExecutablePath, $target, [System.StringComparison]::OrdinalIgnoreCase) }); if ($same.Count -gt 0) { exit 10 }; $other = @($items | Where-Object { -not ($_.ExecutablePath -and [string]::Equals($_.ExecutablePath, $target, [System.StringComparison]::OrdinalIgnoreCase)) }); if ($other.Count -gt 0) { Write-Host '[ERROR] another local_report_server.exe is already running:'; $other | ForEach-Object { if ($_.ExecutablePath) { Write-Host ('  ' + $_.ExecutablePath) } else { Write-Host '  <unknown path>' } }; exit 20 }; exit 0"
if %ERRORLEVEL%==10 exit /b 0
if %ERRORLEVEL%==20 exit /b 1

powershell.exe -NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -Command "Start-Process -FilePath '%TARGET_EXE%' -WorkingDirectory '%~dp0' -WindowStyle Hidden"
exit /b 0
"@ | Set-Content -Path (Join-Path $releaseDir "start_local_report.bat") -Encoding ASCII

@"
@echo off
setlocal
cd /d "%~dp0"

set "TARGET_EXE=%~dp0local_report_server.exe"
if not exist "%TARGET_EXE%" exit /b 0

powershell.exe -NoProfile -ExecutionPolicy Bypass -Command "$target = [System.IO.Path]::GetFullPath('%TARGET_EXE%'); $items = @(Get-CimInstance Win32_Process -Filter 'name = ''local_report_server.exe''' -ErrorAction SilentlyContinue); if (-not $items) { exit 0 }; $same = @($items | Where-Object { $_.ExecutablePath -and [string]::Equals($_.ExecutablePath, $target, [System.StringComparison]::OrdinalIgnoreCase) }); if (-not $same) { $other = @($items | Where-Object { -not ($_.ExecutablePath -and [string]::Equals($_.ExecutablePath, $target, [System.StringComparison]::OrdinalIgnoreCase)) }); if ($other.Count -gt 0) { Write-Host '[WARN] running local_report_server.exe belongs to another directory:'; $other | ForEach-Object { if ($_.ExecutablePath) { Write-Host ('  ' + $_.ExecutablePath) } else { Write-Host '  <unknown path>' } }; exit 2 }; exit 0 }; $same | ForEach-Object { Stop-Process -Id $_.ProcessId -Force -ErrorAction Stop }; Start-Sleep -Milliseconds 800; $left = @(Get-CimInstance Win32_Process -Filter 'name = ''local_report_server.exe''' -ErrorAction SilentlyContinue | Where-Object { $_.ExecutablePath -and [string]::Equals($_.ExecutablePath, $target, [System.StringComparison]::OrdinalIgnoreCase) }); if ($left.Count -gt 0) { exit 1 }"
if %ERRORLEVEL%==2 (
    echo [WARN] current directory has no matching running process; another directory version is running
    exit /b 2
)
if errorlevel 1 (
    echo [ERROR] stop local_report_server failed
    exit /b 1
)
exit /b 0
"@ | Set-Content -Path (Join-Path $releaseDir "stop_local_report.bat") -Encoding ASCII

if ($Zip) {
    $zipPath = Join-Path $distRoot ("{0}_{1}.zip" -f $releaseName, (Get-Date -Format "yyyyMMdd_HHmmss"))
    if (Test-Path $zipPath) { Remove-Item $zipPath -Force }
    Compress-Archive -Path "$releaseDir\*" -DestinationPath $zipPath
    Write-Host "ZIP -> $zipPath"
}

Write-Host "DONE -> $releaseDir"
