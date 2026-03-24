param(
    [string]$DemoSubdir = "viewer_demo",
    [string[]]$Samples = @("runtime_mem_hit", "runtime_multisig", "runtime_noncrypto_multisig"),
    [string]$VmUser = "ubuntu",
    [string]$VmPassword = "rtrace",
    [int]$SshPort = 2222,
    [string]$HostKey = "ssh-ed25519 255 SHA256:FlXcboQ11TAtzuT5nWGuYDCArpjArsycxgE9YKNqNa8"
)

$ErrorActionPreference = "Stop"

$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot "..\..\..")).Path
$demoDir = Join-Path $repoRoot ("artifacts\" + $DemoSubdir)
$plink = Join-Path $env:ProgramFiles "PuTTY\plink.exe"

if (-not (Test-Path $plink)) {
    throw "PuTTY plink not found at '$plink'."
}

New-Item -ItemType Directory -Force -Path $demoDir | Out-Null
Get-ChildItem $demoDir -Force -ErrorAction SilentlyContinue | Remove-Item -Recurse -Force -ErrorAction SilentlyContinue

function Start-Plink {
    param(
        [string]$RemoteCommand,
        [string]$StdoutPath,
        [string]$StderrPath,
        [switch]$Wait
    )

    $quotedHostKey = '"' + $HostKey + '"'
    $args = @(
        "-ssh", "-P", "$SshPort",
        "-l", $VmUser,
        "-pw", $VmPassword,
        "-batch",
        "-hostkey", $quotedHostKey,
        "127.0.0.1",
        $RemoteCommand
    )

    $proc = Start-Process -FilePath $plink -ArgumentList $args -PassThru -NoNewWindow -RedirectStandardOutput $StdoutPath -RedirectStandardError $StderrPath
    if ($Wait) {
        $proc.WaitForExit()
    }
    return $proc
}

function Invoke-Guest {
    param([string]$RemoteCommand)

    $stdout = & $plink `
        -ssh -P $SshPort `
        -l $VmUser `
        -pw $VmPassword `
        -batch `
        -hostkey $HostKey `
        127.0.0.1 `
        $RemoteCommand 2>&1 | Out-String
    $exitCode = $LASTEXITCODE
    $result = [pscustomobject]@{
        ExitCode = $exitCode
        Stdout = $stdout
        Stderr = ""
    }
    if ($exitCode -ne 0) {
        throw "Guest command failed: $RemoteCommand`nOUTPUT:`n$stdout"
    }
    return $result
}

function Start-SampleSession {
    param([string]$Sample)

    $stdout = Join-Path $env:TEMP ($Sample + "_parent_out_" + [guid]::NewGuid().ToString("N") + ".txt")
    $stderr = Join-Path $env:TEMP ($Sample + "_parent_err_" + [guid]::NewGuid().ToString("N") + ".txt")
    $remote = "bash -lc '/samples/$Sample >/tmp/$Sample.log 2>&1 & echo `$!; wait `$!'"
    $proc = Start-Plink -RemoteCommand $remote -StdoutPath $stdout -StderrPath $stderr

    $childPid = $null
    for ($i = 0; $i -lt 20; $i += 1) {
        Start-Sleep -Milliseconds 300
        if (Test-Path $stdout) {
            $text = (Get-Content $stdout -Raw -ErrorAction SilentlyContinue).Trim()
            if ($text -match '^(\d+)$') {
                $childPid = [int]$matches[1]
                break
            }
        }
        $proc.Refresh()
        if ($proc.HasExited) {
            break
        }
    }

    if (-not $childPid) {
        $errText = Get-Content $stderr -Raw -ErrorAction SilentlyContinue
        throw "Failed to start sample '$Sample'. STDERR:`n$errText"
    }

    return [pscustomobject]@{
        Sample = $Sample
        ChildPid = $childPid
        Process = $proc
    }
}

function Stop-SampleSession {
    param($Session)

    try {
        Invoke-Guest "bash -lc 'kill -TERM $($Session.ChildPid) 2>/dev/null || true'" | Out-Null
    } catch {
    }

    try {
        if (-not $Session.Process.WaitForExit(5000)) {
            $Session.Process.Kill()
        }
    } catch {
    }
}

Invoke-Guest "echo $VmPassword | sudo -S bash -lc 'mkdir -p /rules /samples /artifacts/$DemoSubdir; mountpoint -q /rules || mount -t virtiofs rules /rules 2>/dev/null || mount -t 9p -o trans=virtio,version=9p2000.L,msize=262144,ro rules /rules; mountpoint -q /samples || mount -t virtiofs samples /samples 2>/dev/null || mount -t 9p -o trans=virtio,version=9p2000.L,msize=262144,ro samples /samples; mountpoint -q /artifacts || mount -t virtiofs artifacts /artifacts 2>/dev/null || mount -t 9p -o trans=virtio,version=9p2000.L,msize=262144,rw artifacts /artifacts; rm -rf /artifacts/$DemoSubdir/*'" | Out-Null

$results = @()
foreach ($sample in $Samples) {
    $session = Start-SampleSession $sample
    Start-Sleep -Milliseconds 700

    $maxRegionBytes = 16384
    $maxTotalBytes = 524288
    if ($sample -eq "runtime_noncrypto_multisig") {
        $maxRegionBytes = 32768
        $maxTotalBytes = 1048576
    }

    $agentResult = Invoke-Guest "echo $VmPassword | sudo -S bash -lc 'mkdir -p /artifacts/$DemoSubdir && /samples/rtrace-agent --rules-dir /rules --pid $($session.ChildPid) --artifacts-dir /artifacts/$DemoSubdir --once --max-region-bytes $maxRegionBytes --max-total-bytes $maxTotalBytes --verbose'"
    $results += [pscustomobject]@{
        Sample = $sample
        ChildPid = $session.ChildPid
        AgentExitCode = $agentResult.ExitCode
    }

    Stop-SampleSession $session
}

$metaFiles = Get-ChildItem $demoDir -Recurse -Filter meta.json | Sort-Object FullName
$summary = foreach ($file in $metaFiles) {
    $doc = Get-Content $file.FullName -Raw | ConvertFrom-Json
    [pscustomobject]@{
        Path = $file.FullName
        Pid = $doc.pid
        Ppid = $doc.ppid
        Snapshot = Split-Path $file.DirectoryName -Leaf
        HitCount = @($doc.hits).Count
    }
}

Write-Host "[viewer-demo-results]"
$results | Format-Table -AutoSize
Write-Host ""
Write-Host "[viewer-demo-meta]"
$summary | Format-Table -AutoSize
