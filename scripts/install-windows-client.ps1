param(
    [string]$Repo = "dagrigorev/ProtoEPN",
    [string]$Version = "latest",
    [string]$InstallDir = "$env:LOCALAPPDATA\EPN"
)

$ErrorActionPreference = "Stop"

function Get-LatestTag {
    $release = Invoke-RestMethod -Uri "https://api.github.com/repos/$Repo/releases/latest"
    return $release.tag_name
}

if ($Version -eq "latest") {
    $Version = Get-LatestTag
}

$asset = "epn-windows-gui-x86_64-$Version.zip"
$url = "https://github.com/$Repo/releases/download/$Version/$asset"
$zip = Join-Path $env:TEMP $asset

New-Item -ItemType Directory -Force -Path $InstallDir | Out-Null
Write-Host "Downloading $url"
Invoke-WebRequest -Uri $url -OutFile $zip

Expand-Archive -Path $zip -DestinationPath $InstallDir -Force
$exe = Get-ChildItem -Path $InstallDir -Filter epn-windows-gui.exe -Recurse | Select-Object -First 1
if (-not $exe) {
    throw "epn-windows-gui.exe was not found after extraction"
}

Write-Host ""
Write-Host "EPN Windows client installed:"
Write-Host "  $($exe.FullName)"
Write-Host ""
Write-Host "Run it and enter an endpoint URL, for example:"
Write-Host "  epn://YOUR_SERVER_IP:8000"
