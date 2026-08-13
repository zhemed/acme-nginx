<#
.SYNOPSIS
    Quoting-safe SSH command runner for this workspace.

.DESCRIPTION
    Runs a remote bash command through the standard OpenSSH client without
    PowerShell-to-bash quoting conflicts. The command is base64-encoded
    (UTF-8) and decoded remotely, so the bytes that reach bash are exactly
    the string passed to sshx; no local shell interpolation or re-quoting
    can corrupt it.

.PARAMETER Command
    Remote bash command text, passed literally. Use single quotes when
    calling from PowerShell so $() and double quotes reach sshx untouched.

.PARAMETER Encoded
    Alternative: a UTF-8 base64-encoded remote command. Preferred when the
    calling layer (cmd/PowerShell/automation) would otherwise reparse quotes.

.PARAMETER Target
    ssh target or configured OpenSSH alias (required; never stored in this repository).

.PARAMETER ConnectTimeout
    ssh connection timeout in seconds. Default: 8

.EXAMPLE
    .\sshx.ps1 'echo "a; b" && whoami; echo "$(hostname)"'

.NOTES
    Authentication: key-based (BatchMode). No password handling in v1.
#>
[CmdletBinding()]
param(
    [Parameter(Position = 0)]
    [string]$Command,

    [string]$Encoded,

    [string]$Target,

    [int]$ConnectTimeout = 8
)

$ErrorActionPreference = 'Stop'

function Stop-SshxUsage {
    param([string]$Message)

    [Console]::Error.WriteLine("sshx: $Message")
    exit 2
}

if (-not [string]::IsNullOrWhiteSpace($Command) -and -not [string]::IsNullOrWhiteSpace($Encoded)) {
    Stop-SshxUsage 'provide either -Command or -Encoded, not both.'
}

if ([string]::IsNullOrWhiteSpace($Command) -and [string]::IsNullOrWhiteSpace($Encoded)) {
    Stop-SshxUsage 'provide -Command or -Encoded.'
}

if ([string]::IsNullOrWhiteSpace($Target)) {
    Stop-SshxUsage 'provide -Target user@host or an SSH config alias.'
}

if ($ConnectTimeout -lt 1) {
    Stop-SshxUsage 'ConnectTimeout must be at least 1 second.'
}

if (-not [string]::IsNullOrWhiteSpace($Encoded)) {
    $encoded = $Encoded
}
else {
    $bytes = [System.Text.Encoding]::UTF8.GetBytes($Command)
    $encoded = [Convert]::ToBase64String($bytes)
}

# base64 alphabet (A-Za-z0-9+/=) is shell-safe unquoted; the remote command
# therefore contains no quotes that the local or remote shell could mangle.
$remote = "printf %s $encoded | base64 -d | bash"

$sshArguments = @(
    '-o', 'BatchMode=yes',
    '-o', 'StrictHostKeyChecking=yes',
    '-o', "ConnectTimeout=$ConnectTimeout",
    $Target,
    $remote
)

& ssh @sshArguments
exit $LASTEXITCODE
