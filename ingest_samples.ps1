param(
    [string]$ApiUrl = "http://localhost:8000/api/emails/upload"
)

$sampleDir = Join-Path $PSScriptRoot "sample_emails"
$files = Get-ChildItem -Path $sampleDir -Filter "*.eml"

if ($files.Count -eq 0) {
    Write-Host "No sample .eml files found in $sampleDir" -ForegroundColor Red
    exit 1
}

Write-Host "Found $($files.Count) sample email(s). Ingesting to $ApiUrl..." -ForegroundColor Cyan

foreach ($file in $files) {
    Write-Host "
--> Uploading: $($file.Name)" -ForegroundColor Yellow
    try {
        $form = @{
            file = Get-Item -Path $file.FullName
        }
        $response = Invoke-RestMethod -Uri $ApiUrl -Method Post -Form $form
        Write-Host "   [SUCCESS] Email ID: $($response.email_id) | Status: $($response.status)" -ForegroundColor Green
    } catch {
        Write-Host "   [ERROR] Failed to upload $($file.Name): $_" -ForegroundColor Red
    }
}

Write-Host "
All samples uploaded! Check your frontend at http://localhost:5173" -ForegroundColor Green
