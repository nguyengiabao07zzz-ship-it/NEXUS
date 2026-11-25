param(
    [string]$LabHost = '192.168.157.130',
    [string]$LabUser = 'student',
    [ValidateRange(1024,65535)][int]$TunnelPort = 19200,
    [ValidateRange(1024,65535)][int]$Port = 8765,
    [string]$Model = 'gpt-6.1-sol',
    [switch]$CheckOnly
)
$ErrorActionPreference = 'Stop'
if ($LabHost -notmatch '^\d{1,3}(\.\d{1,3}){3}$' -or $LabUser -notmatch '^[a-z_][a-z0-9_-]{0,31}$') {
    throw 'Use the lab IPv4 address and a simple Linux username.'
}
if ($Model -notmatch '^[A-Za-z0-9][A-Za-z0-9_.:/-]{0,127}$') { throw 'Invalid model ID.' }
if ($TunnelPort -ne 19200) { throw 'Current indexer configuration uses port 19200; update it explicitly before using a different port.' }
$python = (Get-Command python -ErrorAction Stop).Source
$entry = Join-Path $PSScriptRoot 'run_nexus.py'
if ($CheckOnly) { & $python $entry --doctor; exit $LASTEXITCODE }
if (Get-NetTCPConnection -LocalPort $Port -State Listen -ErrorAction SilentlyContinue) {
    throw "Port $Port is already in use. Stop the old NEXUS window with Ctrl+C first."
}
$sshProcess = $null
try {
    if (-not (Get-NetTCPConnection -LocalPort $TunnelPort -State Listen -ErrorAction SilentlyContinue)) {
        $ssh = (Get-Command ssh.exe -ErrorAction Stop).Source
        Write-Host 'Starting SSH tunnel. Enter the Ubuntu SSH password if asked; it is not saved.'
        # The existing console is needed for SSH password/host-key interaction.
        $sshProcess = Start-Process -FilePath $ssh -NoNewWindow -PassThru -ArgumentList @(
            '-N','-T','-a','-o','ExitOnForwardFailure=yes','-o','ConnectTimeout=10',
            '-o','ServerAliveInterval=30','-o','ServerAliveCountMax=3',
            '-L',"127.0.0.1:${TunnelPort}:127.0.0.1:9200","${LabUser}@${LabHost}"
        )
        $connected = $false
        for ($attempt=0; $attempt -lt 120; $attempt++) {
            if ($sshProcess.HasExited) { throw 'SSH exited. Check the Ubuntu VM, address, password and host key.' }
            if (Get-NetTCPConnection -LocalPort $TunnelPort -State Listen -ErrorAction SilentlyContinue) { $connected=$true; break }
            Start-Sleep -Milliseconds 500
        }
        if (-not $connected) { throw 'Tunnel did not open within 60 seconds.' }
    }
    Write-Host "NEXUS: http://127.0.0.1:$Port (Codex ChatGPT sign-in; no OpenAI API key)"
    Write-Host 'The next password is the Wazuh Indexer password, not the Ubuntu SSH password.'
    & $python $entry --setup-codex --codex-model $Model --ask-indexer-password --port $Port
    if ($LASTEXITCODE -ne 0) { throw 'NEXUS exited with an error; see the message above.' }
} finally {
    # Only terminate the SSH process created by this launcher, never an existing tunnel.
    if ($null -ne $sshProcess -and -not $sshProcess.HasExited) {
        Stop-Process -Id $sshProcess.Id -ErrorAction SilentlyContinue
    }
}
