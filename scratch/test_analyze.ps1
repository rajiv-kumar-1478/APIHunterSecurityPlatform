$session = New-Object Microsoft.PowerShell.Commands.WebRequestSession
$csrfRes = Invoke-RestMethod -Uri "https://apihunter-api.onrender.com/api/v1/auth/csrf" -Method Get -WebSession $session
$loginHeaders = @{ "X-CSRF-TOKEN" = $csrfRes.csrfToken }
$loginBody = @{
    email = "admin@apihunter.local"
    password = "Rahul@123"
    rememberMe = $false
} | ConvertTo-Json

$loginRes = Invoke-RestMethod -Uri "https://apihunter-api.onrender.com/api/v1/auth/login" -Method Post -Body $loginBody -ContentType "application/json" -Headers $loginHeaders -WebSession $session
Write-Host "Logged in. CSRF:" $loginRes.csrfToken

$postHeaders = @{
    "X-CSRF-TOKEN" = $loginRes.csrfToken
}
$body = @{
    url = "https://github.com/Dina1moh/AI-Contract-Review-App/blob/cde16f45a0979cd"
} | ConvertTo-Json

try {
    $res = Invoke-RestMethod -Uri "https://apihunter-api.onrender.com/api/v1/apihunter/analyze-url" -Method Post -Body $body -ContentType "application/json" -Headers $postHeaders -WebSession $session
    Write-Host "Analyze Success:" ($res | ConvertTo-Json)
} catch {
    Write-Host "Analyze Failed with error:" $_.Exception.Message
    if ($_.Exception.Response) {
        $stream = $_.Exception.Response.GetResponseStream()
        $reader = New-Object System.IO.StreamReader($stream)
        Write-Host "Response Body:" $reader.ReadToEnd()
    }
}
