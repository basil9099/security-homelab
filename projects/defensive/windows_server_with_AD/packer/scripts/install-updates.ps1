# Best-effort Windows Update pass. Skipped in CI builds (set SKIP_UPDATES=1).

if ($env:SKIP_UPDATES -eq '1') {
  Write-Host "SKIP_UPDATES=1 — skipping Windows Update"
  return
}

$ErrorActionPreference = 'Continue'

Install-PackageProvider -Name NuGet -Force -Scope AllUsers | Out-Null
Install-Module -Name PSWindowsUpdate -Force -Scope AllUsers -AllowClobber | Out-Null
Import-Module PSWindowsUpdate

Get-WindowsUpdate -AcceptAll -Install -IgnoreReboot -Verbose
