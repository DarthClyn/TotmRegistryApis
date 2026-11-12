# Lists the Alpha ID inbox (files PILA sent), downloads one eLC, reads its VC ID / issuer / holder from the token, and
# asks PILA's verification context about THAT credential.
#   .\scripts\check-inbox-elc.ps1                                   (newest file whose name contains "BETA")
#   .\scripts\check-inbox-elc.ps1 -Name BETA-elc-test-20261112.json
# Keys are read from ..\AplhaIDPortalFe\.env (ADMIN_API_KEY, PILA_PARTNER_API_KEY) and never printed.
param(
  [string]$Name = "BETA",
  [string]$Api = "https://totmregistryapis-production.up.railway.app/api/v1",
  [string]$NdaKey = "https://elc-beta.ndakey.vn/api/v1",
  [string]$Out = "$PSScriptRoot\..\..\Portal Docs"
)
$envFile = "$PSScriptRoot\..\..\AplhaIDPortalFe\.env"
function EnvVal($k) { $l = Get-Content $envFile | Where-Object { $_ -match "^\s*$k\s*=" } | Select-Object -First 1; if ($l) { ($l -split '=', 2)[1].Trim().Trim('"', "'") } }
$admin = EnvVal "ADMIN_API_KEY"; $pila = EnvVal "PILA_PARTNER_API_KEY"
if (-not $admin -or -not $pila) { Write-Host "ADMIN_API_KEY or PILA_PARTNER_API_KEY missing in $envFile" -ForegroundColor Red; exit 1 }

Write-Host "== Inbox (newest first)" -ForegroundColor Cyan
$files = (Invoke-RestMethod -Uri "$Api/totm/inbox?limit=20" -Headers @{ "X-Admin-Key" = $admin }).data.files
$files | Select-Object -First 10 | ForEach-Object { "  {0,-36} {1,-20} {2}  {3}" -f $_.fileName, $_.contentType, $_.sentAt, $_.fileId }

$f = $files | Where-Object { $_.fileName -like "*$Name*" } | Select-Object -First 1
if (-not $f) { Write-Host "No inbox file matching '$Name'" -ForegroundColor Red; exit 1 }
Write-Host "`n== Downloading $($f.fileName)" -ForegroundColor Cyan
New-Item -ItemType Directory -Force -Path $Out | Out-Null
$path = Join-Path $Out $f.fileName
Invoke-WebRequest -Uri "$Api/totm/inbox/$($f.fileId)" -Headers @{ "X-Admin-Key" = $admin } -OutFile $path -UseBasicParsing
Write-Host "  saved to $path"

# The token: the file itself (.jwt) or the "vc" field of PILA's JSON wrapper.
$text = (Get-Content $path -Raw).Trim()
try { $o = $text | ConvertFrom-Json; $jwt = if ($o.vc) { $o.vc } else { $text } } catch { $jwt = $text }
$p = $jwt.Split('.')[1].Replace('-', '+').Replace('_', '/'); $p += '=' * ((4 - $p.Length % 4) % 4)
$claims = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($p)) | ConvertFrom-Json
$vcId = if ($claims.vc.id) { $claims.vc.id } else { $claims.jti }
$iss = if ($claims.vc.issuer) { $claims.vc.issuer } else { $claims.iss }
$holder = if ($claims.vc.credentialSubject.id) { $claims.vc.credentialSubject.id } else { $claims.sub }
"  LC number : $($claims.vc.credentialSubject.lcNumber)"
"  VC ID     : $vcId"
"  issuer    : $iss"
"  holder    : $holder"

Write-Host "`n== PILA verification context for this credential" -ForegroundColor Cyan
$body = @{ holderDid = $holder; vcIds = @(@{ vcId = $vcId; issuerDid = $iss }) } | ConvertTo-Json -Depth 5 -Compress
try {
  $r = Invoke-WebRequest -Method Post -Uri "$NdaKey/vp/verification-context" -Headers @{ "X-Api-Key" = $pila } -ContentType "application/json" -Body $body -UseBasicParsing
  Write-Host ("  " + $r.Content) -ForegroundColor Green
} catch { Write-Host ("  " + $_.ErrorDetails.Message) -ForegroundColor Red }
