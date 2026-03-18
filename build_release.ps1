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

if not exist "%~dp0local_report_server.exe" (
    echo [ERROR] local_report_server.exe not found
    pause
    exit /b 1
)

tasklist /FI "IMAGENAME eq local_report_server.exe" 2>NUL | find /I "local_report_server.exe" >NUL
if not errorlevel 1 exit /b 0

powershell.exe -NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -Command "Start-Process -FilePath '%~dp0local_report_server.exe' -WorkingDirectory '%~dp0' -WindowStyle Hidden"
exit /b 0
"@ | Set-Content -Path (Join-Path $releaseDir "start_local_report.bat") -Encoding ASCII

@"
@echo off
setlocal

tasklist /FI "IMAGENAME eq local_report_server.exe" 2>NUL | find /I "local_report_server.exe" >NUL
if errorlevel 1 exit /b 0

taskkill /F /IM local_report_server.exe >NUL 2>&1
exit /b 0
"@ | Set-Content -Path (Join-Path $releaseDir "stop_local_report.bat") -Encoding ASCII

if ($Zip) {
    $zipPath = Join-Path $distRoot ("{0}_{1}.zip" -f $releaseName, (Get-Date -Format "yyyyMMdd_HHmmss"))
    if (Test-Path $zipPath) { Remove-Item $zipPath -Force }
    Compress-Archive -Path "$releaseDir\*" -DestinationPath $zipPath
    Write-Host "ZIP -> $zipPath"
}

Write-Host "DONE -> $releaseDir"
