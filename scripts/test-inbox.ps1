# Inbox smoke test against a deployed TOTM Trust API. Sends one file each way, lists, downloads, acks. Deletes nothing.
# Usage (from the repo folder):
#   powershell -ExecutionPolicy Bypass -File scripts\test-inbox.ps1            (default: the production base URL)
#   ... -Url https://<other-host>                                                   (another deployment)
#   ... -PartnerKey tta_...   (optional: PILA's calls use the partner key instead of the admin key)
param(
  [string]$Url = "https://totmregistryapis-production.up.railway.app",
  [string]$PartnerKey,
  [string]$File = "elc.json"
)
$ErrorActionPreference = "Stop"
$B = ($Url.TrimEnd("/") -replace "/api/v1$", "") + "/api/v1"
Write-Host "Testing $B"

$admin = (Select-String -Path .env -Pattern '^ADMIN_API_KEY=(.*)$').Matches[0].Groups[1].Value.Trim('"')
if (-not $admin) { throw "ADMIN_API_KEY not found in .env" }
$HT = @{ "X-Admin-Key" = $admin }                                         # TOTM side
$HP = if ($PartnerKey) { @{ "X-Api-Key" = $PartnerKey } } else { $HT }    # PILA side
$who = if ($PartnerKey) { "partner key" } else { "admin key" }

function Step($t) { Write-Host "`n== $t" -ForegroundColor Cyan }
function Ok($t)   { Write-Host "   OK  $t" -ForegroundColor Green }
function Show($r) { $r | Format-List | Out-String | Write-Host }
function Call($m, $u, $h) {
  try { Invoke-RestMethod -Method $m -Uri $u -Headers $h }
  catch {
    $body = $_.ErrorDetails.Message
    Write-Host "   FAIL $m $u -> $($_.Exception.Message) $body" -ForegroundColor Red
    exit 1
  }
}

Step "Health"
Show (Call Get "$B/health" @{}).data

Step "TOTM sends $File -> PILA inbox"
$s1 = Invoke-RestMethod -Method Post -Uri "$B/totm/send?fileName=$(Split-Path $File -Leaf)&note=inbox-test" -Headers $HT -ContentType "application/json" -InFile $File
Show $s1.data; $id1 = $s1.data.fileId; Ok "fileId $id1"

Step "PILA sends a small PDF -> TOTM inbox ($who)"
$pdf = Join-Path $env:TEMP "inbox-test.pdf"
[IO.File]::WriteAllText($pdf, "%PDF-1.4`n% inbox test $(Get-Date -Format o)`n%%EOF`n")
$s2 = Invoke-RestMethod -Method Post -Uri "$B/pila/send?fileName=inbox-test.pdf&note=inbox-test" -Headers $HP -ContentType "application/pdf" -InFile $pdf
Show $s2.data; $id2 = $s2.data.fileId; Ok "fileId $id2"

Step "PILA inbox (should contain $id1)"
$pi = (Call Get "$B/pila/inbox" $HP).data
$pi.files | Select-Object fileId, from, to, fileName, size, sentAt, readAt | Format-Table -AutoSize | Out-String | Write-Host
if ($pi.files.fileId -contains $id1) { Ok "found" } else { Write-Host "   FAIL not in PILA inbox" -ForegroundColor Red }

Step "TOTM inbox (should contain $id2)"
$ti = (Call Get "$B/totm/inbox" $HT).data
$ti.files | Select-Object fileId, from, to, fileName, size, sentAt, readAt | Format-Table -AutoSize | Out-String | Write-Host
if ($ti.files.fileId -contains $id2) { Ok "found" } else { Write-Host "   FAIL not in TOTM inbox" -ForegroundColor Red }

Step "PILA downloads $id1 and compares hashes"
$out = Join-Path $env:TEMP "inbox-download-$id1.json"
$resp = Invoke-WebRequest -Uri "$B/pila/inbox/$id1" -Headers $HP -OutFile $out -PassThru -UseBasicParsing
$hdr = "$($resp.Headers['X-File-Sha256'])"
$mine = (Get-FileHash $out -Algorithm SHA256).Hash.ToLower()
$orig = (Get-FileHash $File -Algorithm SHA256).Hash.ToLower()
Write-Host "   original  $orig`n   download  $mine`n   header    $hdr"
if ($mine -eq $orig -and $mine -eq $hdr) { Ok "identical" } else { Write-Host "   FAIL hash mismatch" -ForegroundColor Red }

Step "PILA acks $id1"
$a = (Call Post "$B/pila/inbox/$id1/ack" $HP).data
Ok "readAt $($a.readAt) by $($a.readBy)"

Step "TOTM sent box (readAt now set on $id1)"
(Call Get "$B/totm/sent" $HT).data.files | Select-Object fileId, to, fileName, sentAt, readAt, readBy | Format-Table -AutoSize | Out-String | Write-Host

Write-Host "`nDone. Nothing was deleted: check the Blob store under inbox/pila/$id1 and inbox/totm/$id2." -ForegroundColor Cyan
Write-Host "Downloaded copy: $out"
