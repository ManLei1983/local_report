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
if ($IncludeEnv -and (Test-Path "$root\.env")) {
    Copy-Item "$root\.env" "$releaseDir\.env" -Force
}
if ($IncludeDb -and (Test-Path "$root\local_report.db")) {
    Copy-Item "$root\local_report.db" "$releaseDir\local_report.db" -Force
}

@"
@echo off
cd /d %~dp0
local_report_server.exe
pause
"@ | Set-Content -Path (Join-Path $releaseDir "start_local_report.bat") -Encoding ASCII

if ($Zip) {
    $zipPath = Join-Path $distRoot ("{0}_{1}.zip" -f $releaseName, (Get-Date -Format "yyyyMMdd_HHmmss"))
    if (Test-Path $zipPath) { Remove-Item $zipPath -Force }
    Compress-Archive -Path "$releaseDir\*" -DestinationPath $zipPath
    Write-Host "ZIP -> $zipPath"
}

Write-Host "DONE -> $releaseDir"
