# Enrol Elastic Agent into Fleet (SPEC §5.1). Requires FLEET_URL and ENROLL_TOKEN env vars, which
# you get from Kibana > Fleet after starting docker-compose.lab.yml. If unset, this is a no-op so
# `vagrant up` still succeeds for offline users.
$ErrorActionPreference = "Stop"
if (-not $env:FLEET_URL -or -not $env:ENROLL_TOKEN) {
    Write-Host "FLEET_URL / ENROLL_TOKEN not set; skipping Elastic Agent enrolment."
    exit 0
}
$ver = "8.15.3"
$dir = "C:\Tools\elastic-agent-$ver-windows-x86_64"
if (-not (Test-Path $dir)) {
    $zip = "C:\Tools\elastic-agent-$ver.zip"
    Invoke-WebRequest -Uri "https://artifacts.elastic.co/downloads/beats/elastic-agent/elastic-agent-$ver-windows-x86_64.zip" -OutFile $zip
    Expand-Archive $zip -DestinationPath "C:\Tools" -Force
}
& "$dir\elastic-agent.exe" install --url=$env:FLEET_URL --enrollment-token=$env:ENROLL_TOKEN `
    --insecure --force
Write-Host "Elastic Agent enrolled to $env:FLEET_URL"
