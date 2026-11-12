# Calls PILA's verification context (NDAKey POST /vp/verification-context) for BETALC260001 three ways, to see if the
# holder DID changes the answer. The issuer DID is always sent in vcIds[].issuerDid.
#   .\scripts\test-context.ps1            (key read from ..\AplhaIDPortalFe\.env, PILA_PARTNER_API_KEY; never printed)
param(
  [string]$ApiKey,
  [string]$Base = "https://elc-beta.ndakey.vn/api/v1",
  [string]$VcId = "urn:uuid:f892a660-d31c-478e-beeb-7efa4e9e40c7",
  [string]$Issuer = "did:nda:testnet:0x2ea525db609113e2efb306548f72f46ebd379871",
  [string]$Holder = "did:web:elc.bankalpha.example"
)
if (-not $ApiKey) {
  foreach ($f in "$PSScriptRoot\..\.env", "$PSScriptRoot\..\..\AplhaIDPortalFe\.env") {
    if (Test-Path $f) {
      $line = Get-Content $f | Where-Object { $_ -match '^\s*PILA_PARTNER_API_KEY\s*=' } | Select-Object -First 1
      if ($line) { $ApiKey = ($line -split '=', 2)[1].Trim().Trim('"', "'"); break }
    }
  }
}
if (-not $ApiKey) { Write-Host "PILA_PARTNER_API_KEY not found" -ForegroundColor Red; exit 1 }

function Ask($label, $body) {
  Write-Host "`n== $label" -ForegroundColor Cyan
  Write-Host ("   sent: " + ($body | ConvertTo-Json -Depth 5 -Compress))
  try {
    $r = Invoke-WebRequest -Method Post -Uri "$Base/vp/verification-context" -Headers @{ "X-Api-Key" = $ApiKey } `
      -ContentType "application/json" -Body ($body | ConvertTo-Json -Depth 5 -Compress) -TimeoutSec 20 -UseBasicParsing
    Write-Host ("   " + [int]$r.StatusCode + "  " + $r.Content) -ForegroundColor Green
  } catch {
    Write-Host ("   " + [int]$_.Exception.Response.StatusCode + "  " + $_.ErrorDetails.Message) -ForegroundColor Red
  }
}

$vc = @(@{ vcId = $VcId; issuerDid = $Issuer })
Ask "1. holder = the eLC's holder ($Holder)" @{ holderDid = $Holder; vcIds = $vc }
Ask "2. holder = the issuer itself"            @{ holderDid = $Issuer; vcIds = $vc }
Ask "3. no holder"                             @{ vcIds = $vc }
Write-Host "`n== 4. our key check (GET /partners/me)" -ForegroundColor Cyan
try { $me = Invoke-RestMethod -Uri "$Base/partners/me" -Headers @{ "X-Api-Key" = $ApiKey } -TimeoutSec 20; Write-Host ("   " + ($me | ConvertTo-Json -Compress)) -ForegroundColor Green } catch { Write-Host ("   " + $_.ErrorDetails.Message) -ForegroundColor Red }
