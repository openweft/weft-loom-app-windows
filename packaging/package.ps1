# Assemble and (optionally) sign an MSIX for weft-app-windows.
#
#   pwsh packaging/package.ps1 [-OutDir dist]
#
# Requires the Windows SDK (makeappx.exe, signtool.exe) on PATH. Signing
# is left to CI (needs a cert); this produces the unsigned .msix for local
# testing — sideload after trusting a self-signed test cert.
param(
    [string]$OutDir = "dist"
)
$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $PSScriptRoot
$stage = Join-Path $OutDir "msix-stage"

Write-Host "==> building binary"
$env:CGO_ENABLED = "1"
& go build -ldflags "-H windowsgui" -o (Join-Path $root "weft-app-windows.exe") $root

Write-Host "==> staging $stage"
Remove-Item -Recurse -Force $stage -ErrorAction SilentlyContinue
New-Item -ItemType Directory -Force -Path (Join-Path $stage "Images") | Out-Null
Copy-Item (Join-Path $root "weft-app-windows.exe") $stage
Copy-Item (Join-Path $PSScriptRoot "AppxManifest.xml") $stage

# Generate the required logo sizes from assets/icon.png.
# TODO: use a proper image tool; these sizes are what the manifest needs.
$icon = Join-Path $root "assets/icon.png"
foreach ($logo in @("StoreLogo.png","Square150x150Logo.png","Square44x44Logo.png","Wide310x150Logo.png")) {
    Copy-Item $icon (Join-Path $stage "Images" $logo)
}

Write-Host "==> makeappx"
& makeappx pack /d $stage /p (Join-Path $OutDir "WeftApp.msix") /overwrite

Write-Host "==> done. Sign in CI:"
Write-Host '    signtool sign /fd SHA256 /a /f cert.pfx /p $env:CERT_PW dist\WeftApp.msix'
