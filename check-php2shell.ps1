# check-php2shell.ps1 - find PHP installs on a Windows host and tell you whether
# they are vulnerable to php2shell (CVE-2026-109618 / CVE-2026-109619).
#
# Read-only. Run from an elevated PowerShell for full coverage:
#   powershell -ExecutionPolicy Bypass -File .\check-php2shell.ps1
#
# Exit codes: 0 = nothing vulnerable found, 1 = vulnerable PHP found, 2 = needs review.

$ErrorActionPreference = 'SilentlyContinue'
$Fixed = @{ '8.5' = 12; '8.4' = 27; '8.3' = 36; '8.2' = 35 }

$roots = @(
  'C:\php', 'C:\xampp', 'C:\wamp', 'C:\wamp64', 'C:\laragon', 'C:\tools',
  'C:\inetpub', $env:ProgramFiles, ${env:ProgramFiles(x86)}, $env:ProgramData,
  "$env:LOCALAPPDATA\Programs"
) | Where-Object { $_ -and (Test-Path $_) }

$exes = @()
$exes += Get-Command php.exe, php-cgi.exe -All | ForEach-Object { $_.Source }
foreach ($r in $roots) {
  $exes += Get-ChildItem -Path $r -Recurse -Depth 6 -File -Include php.exe, php-cgi.exe |
    ForEach-Object { $_.FullName }
}
$exes = $exes | Where-Object { $_ } | Sort-Object -Unique

$vuln = 0; $review = 0; $ok = 0
Write-Host "== PHP installs on $env:COMPUTERNAME =="
foreach ($exe in $exes) {
  $out = & $exe -n -v 2>&1 | Out-String
  if ($out -notmatch 'PHP (\d+)\.(\d+)\.(\d+)') { continue }
  $maj = [int]$Matches[1]; $min = [int]$Matches[2]; $pat = [int]$Matches[3]
  $ver = "$maj.$min.$pat"; $branch = "$maj.$min"
  if ($Fixed.ContainsKey($branch)) {
    if ($pat -ge $Fixed[$branch]) {
      $ok++; Write-Host "  [PATCHED]    $exe  PHP $ver" -ForegroundColor Green
    } else {
      $vuln++; Write-Host "  [VULNERABLE] $exe  PHP $ver  (upgrade to $branch.$($Fixed[$branch]) or later)" -ForegroundColor Red
    }
  } elseif ($maj -gt 8 -or ($maj -eq 8 -and $min -ge 6)) {
    $review++; Write-Host "  [REVIEW]     $exe  PHP $ver  (branch not covered by the advisory, check php.net)" -ForegroundColor Yellow
  } else {
    $vuln++; Write-Host "  [VULNERABLE] $exe  PHP $ver  (end-of-life, no official fix; upgrade to 8.2+)" -ForegroundColor Red
  }
}
if ($exes.Count -eq 0) { Write-Host "  no PHP installs found" }

Write-Host ""
Write-Host "== Is PHP serving web requests right now? =="
$web = Get-Process php-cgi, httpd, w3wp -ErrorAction SilentlyContinue |
  Group-Object ProcessName | ForEach-Object { "  $($_.Count) x $($_.Name)" }
if ($web) { $web | Write-Host } else { Write-Host "  no php-cgi / httpd / IIS worker processes running" }

Write-Host ""
if ($vuln -gt 0) {
  Write-Host "RESULT: VULNERABLE ($vuln install(s)). Install 8.5.12 / 8.4.27 / 8.3.36 / 8.2.35 from windows.php.net, then restart IIS/Apache." -ForegroundColor Red
  exit 1
} elseif ($review -gt 0) {
  Write-Host "RESULT: REVIEW ($review item(s) need a manual look)" -ForegroundColor Yellow
  exit 2
} else {
  Write-Host "RESULT: OK ($ok patched install(s) found)" -ForegroundColor Green
  exit 0
}
