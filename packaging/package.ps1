# Assemble and (optionally) sign an MSIX for weft-app-windows.
#
#   pwsh packaging/package.ps1 [-OutDir dist]
#
# Requires the Windows SDK (makeappx.exe, signtool.exe); it is located under
# the SDK when it is not on PATH, which is the case on GitHub runners. Signing
# is left to CI (needs a cert); this produces the unsigned .msix for local
# testing — sideload after trusting a self-signed test cert.
param(
    [string]$OutDir = "dist"
)
$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $PSScriptRoot
$stage = Join-Path $OutDir "msix-stage"

# makeappx.exe and signtool.exe ship with the Windows SDK, which IS installed
# on GitHub's windows runners -- but its bin directory is not on PATH, so a
# bare `makeappx` there fails with "The term 'makeappx' is not recognized".
# Look the tool up under the SDK when PATH does not already provide it.
function Resolve-SdkTool {
    param([Parameter(Mandatory)][string]$Name)

    $onPath = Get-Command $Name -ErrorAction SilentlyContinue
    if ($onPath) { return $onPath.Source }

    # Guard the environment variables before Join-Path: it throws on a null
    # Path, which would replace the useful "not found" message below with
    # "Cannot bind argument to parameter 'Path'" anywhere they are unset.
    $roots = @()
    foreach ($base in @(${env:ProgramFiles(x86)}, $env:ProgramFiles)) {
        if ([string]::IsNullOrEmpty($base)) { continue }
        $dir = Join-Path $base 'Windows Kits\10\bin'
        if (Test-Path $dir) { $roots += $dir }
    }

    # Prefer the highest SDK version, and the x64 build within it. Compare
    # versions numerically: 10.0.26100.0 must beat 10.0.9999.0, which a plain
    # string sort gets backwards.
    $candidates = foreach ($root in $roots) {
        Get-ChildItem -Path $root -Filter $Name -Recurse -ErrorAction SilentlyContinue |
            Where-Object { $_.FullName -match '\\x64\\' }
    }
    $best = $candidates | Sort-Object -Property @{Expression = {
        if ($_.FullName -match '\\10\\bin\\(\d+(?:\.\d+)+)\\') { [version]$Matches[1] } else { [version]'0.0' }
    }} -Descending | Select-Object -First 1

    if (-not $best) {
        throw "$Name not found on PATH or under the Windows SDK. Install the Windows 10/11 SDK."
    }
    Write-Host "    using $($best.FullName)"
    return $best.FullName
}

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
$makeappx = Resolve-SdkTool -Name "makeappx.exe"
& $makeappx pack /d $stage /p (Join-Path $OutDir "WeftApp.msix") /overwrite

Write-Host "==> done. Sign in CI:"
Write-Host '    signtool sign /fd SHA256 /a /f cert.pfx /p $env:CERT_PW dist\WeftApp.msix'
