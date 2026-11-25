param(
    [ValidatePattern('^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$')]
    [string]$SshHost = '192.168.157.130',
    [ValidatePattern('^[a-z_][a-z0-9_-]{0,31}$')]
    [string]$SshUser = 'student',
    [ValidateRange(1, 65535)]
    [int]$SshPort = 22,
    [ValidateRange(1024, 65535)]
    [int]$LocalPort = 19200
)

$ErrorActionPreference = 'Stop'
$nexusParsedAddress = $null
if (-not [Net.IPAddress]::TryParse($SshHost, [ref]$nexusParsedAddress)) {
    throw 'Invalid Ubuntu IPv4 address.'
}
$nexusSshCommand = Get-Command ssh.exe -CommandType Application -ErrorAction Stop
$nexusForward = '127.0.0.1:{0}:127.0.0.1:9200' -f $LocalPort
$nexusDestination = '{0}@{1}' -f $SshUser, $SshHost

Write-Host ('NEXUS: localhost:{0} -> Ubuntu localhost:9200 via SSH.' -f $LocalPort)
Write-Host 'Keep this terminal open. Ctrl+C stops the tunnel.'
Write-Host 'On first connection, compare the host fingerprint with the Ubuntu console before accepting.'
Write-Host 'Passwords are entered directly in SSH; this script does not store them.'
& $nexusSshCommand.Source -N -T -a -p $SshPort `
    -o ExitOnForwardFailure=yes -o ServerAliveInterval=30 `
    -o ServerAliveCountMax=3 -o StrictHostKeyChecking=ask `
    -L $nexusForward $nexusDestination
if ($LASTEXITCODE -ne 0) {
    throw 'SSH tunnel stopped with an error. Check VM, authentication, host key and local port.'
}
