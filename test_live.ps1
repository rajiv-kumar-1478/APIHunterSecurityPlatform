$session = New-Object Microsoft.PowerShell.Commands.WebRequestSession

Write-Host "1. Getting CSRF token..."
$csrfRes = Invoke-RestMethod -Uri "https://apihunter-api.onrender.com/api/v1/auth/csrf" -Method Get -WebSession $session
Write-Host "CSRF Token:" $csrfRes.csrfToken

Write-Host "`n2. Logging in..."
$loginHeaders = @{
    "X-CSRF-TOKEN" = $csrfRes.csrfToken
}
$loginBody = @{
    email = "admin@apihunter.local"
    password = "Rnl63PzkxpxGrwDt2tLw0msVzxgHyZYHWTWiqHGH7hM="
    rememberMe = $false
} | ConvertTo-Json

try {
    $loginRes = Invoke-RestMethod -Uri "https://apihunter-api.onrender.com/api/v1/auth/login" -Method Post -Body $loginBody -ContentType "application/json" -Headers $loginHeaders -WebSession $session
    Write-Host "Login Success!" ($loginRes | ConvertTo-Json)
} catch {
    Write-Host "Login Error:" $_.Exception.Message
    if ($_.ErrorDetails) { Write-Host "Details:" $_.ErrorDetails.Message }
}

Write-Host "`n3. Calling summary..."
try {
    $sumRes = Invoke-RestMethod -Uri "https://apihunter-api.onrender.com/api/v1/apihunter/summary" -Method Get -WebSession $session
    Write-Host "Summary Response:" ($sumRes | ConvertTo-Json)
} catch {
    Write-Host "Summary Error:" $_.Exception.Message
    if ($_.ErrorDetails) { Write-Host "Details:" $_.ErrorDetails.Message }
}

Write-Host "`n4. Calling records..."
try {
    $recRes = Invoke-RestMethod -Uri "https://apihunter-api.onrender.com/api/v1/apihunter/records?status=all&page=1&pageSize=15" -Method Get -WebSession $session
    Write-Host "Records Response:" ($recRes | ConvertTo-Json)
} catch {
    Write-Host "Records Error:" $_.Exception.Message
    if ($_.ErrorDetails) { Write-Host "Details:" $_.ErrorDetails.Message }
}

Write-Host "`n5. Calling sync..."
try {
    $syncRes = Invoke-RestMethod -Uri "https://apihunter-api.onrender.com/api/v1/apihunter/sync" -Method Post -Headers $loginHeaders -WebSession $session
    Write-Host "Sync Response:" ($syncRes | ConvertTo-Json)
} catch {
    Write-Host "Sync Error:" $_.Exception.Message
    if ($_.ErrorDetails) { Write-Host "Details:" $_.ErrorDetails.Message }
}
