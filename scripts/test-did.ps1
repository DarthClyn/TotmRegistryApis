# Looks up PILA issuer DIDs, with and without our NDAKey key, on both lookups the PILA verifier uses:
#   1. NDAKey registry  GET {NDAKEY}/dids/{did}
#   2. PILA DID resolver GET {RESOLVER}/{did}   (the one that answered 403)
#   .\scripts\test-did.ps1                         (key read from ..\AplhaIDPortalFe\.env, PILA_PARTNER_API_KEY)
#   .\scripts\test-did.ps1 -ApiKey <key> -Did did:nda:testnet:0x...
param(
  [string]$ApiKey,
  [string[]]$Did = @(
    "did:nda:testnet:0x2ea525db609113e2efb306548f72f46ebd379871",  # Bank Beta, BETALC260001 (403 in the portal)
    "did:nda:testnet:0xe71963787f8d5e328cd12b7a78b0d26062e1f31e"   # earlier PILA eLC (worked)
  ),
  [string]$NdaKey = "https://api-beta.ndakey.vn/service/api/v1",
  [string]$Resolver = "https://api.ndadid.vn/api/v1/did"
)
if (-not $ApiKey) {
  foreach ($f in "$PSScriptRoot\..\.env", "$PSScriptRoot\..\..\AplhaIDPortalFe\.env") {
    if (Test-Path $f) {
      $line = Get-Content $f | Where-Object { $_ -match '^\s*PILA_PARTNER_API_KEY\s*=' } | Select-Object -First 1
      if ($line) { $ApiKey = ($line -split '=', 2)[1].Trim().Trim('"', "'"); break }
    }
  }
}
Write-Host "NDAKey key: $(if ($ApiKey) { 'found' } else { 'NOT found (only the no-key calls will run)' })"

function Try-Get($label, $url, $withKey) {
  $h = @{}; if ($withKey) { $h["X-Api-Key"] = $ApiKey }
  try {
    $r = Invoke-WebRequest -Uri $url -Headers $h -TimeoutSec 20 -UseBasicParsing
    $body = $r.Content; $code = [int]$r.StatusCode
  } catch {
    $code = [int]$_.Exception.Response.StatusCode; $body = $_.ErrorDetails.Message
  }
  $color = if ($code -eq 200) { "Green" } else { "Red" }
  $short = if ($body) { ($body -replace '\s+', ' ').Substring(0, [Math]::Min(160, $body.Length)) } else { "" }
  Write-Host ("  {0,-34} {1}  {2}" -f $label, $code, $short) -ForegroundColor $color
}

foreach ($d in $Did) {
  Write-Host "`n== $d" -ForegroundColor Cyan
  Try-Get "NDAKey registry, no key"      "$NdaKey/dids/$d" $false
  if ($ApiKey) { Try-Get "NDAKey registry, with key"    "$NdaKey/dids/$d" $true }
  Try-Get "PILA DID resolver, no key"    "$Resolver/$d" $false
  if ($ApiKey) { Try-Get "PILA DID resolver, with key"  "$Resolver/$d" $true }
}
