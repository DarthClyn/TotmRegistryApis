# Tests PILA verification on a deployed TOTM Trust API: verifier up, a real PILA eLC verifies, a changed one fails.
#   .\scripts\test-pila.ps1 -AdminKey tta_...                       (production)
#   .\scripts\test-pila.ps1 -AdminKey tta_... -Url https://<other-host>
param(
  [Parameter(Mandatory = $true)][string]$AdminKey,
  [string]$Url = "https://totmregistryapis-production.up.railway.app",
  [string]$File = "$PSScriptRoot\..\test\fixtures\sample-pila-elc.jwt"
)
$ErrorActionPreference = "Stop"
$api = "$($Url.TrimEnd('/'))/api/v1"
$h = @{ "X-Admin-Key" = $AdminKey }

function Call($name, $method, $path, $body) {
  Write-Host "`n== $name" -ForegroundColor Cyan
  try {
    $req = @{ Method = $method; Uri = "$api$path"; Headers = $h; TimeoutSec = 90 }
    if ($body) { $req.Body = ($body | ConvertTo-Json -Depth 50 -Compress); $req.ContentType = "application/json" }
    $r = Invoke-RestMethod @req
    return $r.data
  } catch {
    Write-Host "HTTP $($_.Exception.Response.StatusCode.value__): $($_.ErrorDetails.Message)" -ForegroundColor Red
    return $null
  }
}

$health = Call "PILA verifier health" GET "/pila/health"
if ($health) { $health | Format-List mode, sdk, verifierKey, ndakey, resolver }

$jwt = (Get-Content $File -Raw).Trim()
$r = Call "Verify PILA eLC ($([IO.Path]::GetFileName($File)))" POST "/pila/verify" @{ credential = $jwt }
if ($r) {
  "format     : $($r.format)"
  "vcId       : $($r.id)"
  "issuer     : $($r.issuer)"
  foreach ($k in "issuer", "signature", "expiration", "revocation") {
    $c = $r.checks.$k; "check $($k.PadRight(10)): " + $(if ($c.skipped) { "skipped" } elseif ($c.passed) { "PASS" } else { "FAIL  $($c.error)" })
  }
  "NDAKey     : called=$($r.ndakey.called) status=$($r.ndakey.status) trusted=$($r.ndakey.isIssuerTrusted) $($r.ndakey.error)$($r.ndakey.skipped)"
}

# Change one character of the payload: the signature check must fail.
$p = $jwt.Split('.'); $mid = $p[1].ToCharArray(); $i = [int]($mid.Length / 2); $mid[$i] = $(if ($mid[$i] -eq 'A') { 'B' } else { 'A' }); $p[1] = -join $mid
$t = Call "Verify the same eLC with one character changed (expect signature FAIL or 400)" POST "/pila/verify" @{ credential = ($p -join '.') }
if ($t) { "signature  : " + $(if ($t.checks.signature.passed) { "PASS (unexpected!)" } else { "FAIL (expected)  $($t.checks.signature.error)" }) }
