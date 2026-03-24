param(
    [string]$Distro = "Ubuntu",
    [string]$RepoPath = "",
    [string]$BaseImage = "vm/simple_ubuntu.qcow2",
    [string]$OverlayImage = "vm/overlay.qcow2",
    [string]$SampleBinary = "runtime_eicar",
    [ValidateSet("none", "gtk", "curses")]
    [string]$DisplayBackend = "none",
    [ValidateSet("auto", "on", "off")]
    [string]$UseKvm = "auto",
    [int]$MemoryMb = 4096,
    [int]$CpuCount = 2,
    [int]$SshPort = 2222,
    [string]$VmUser = "ubuntu",
    [string]$VmPassword = "rtrace",
    [string]$HostKey = "ssh-ed25519 255 SHA256:FlXcboQ11TAtzuT5nWGuYDCArpjArsycxgE9YKNqNa8",
    [switch]$SkipBuild
)

$ErrorActionPreference = "Stop"

if ([string]::IsNullOrWhiteSpace($RepoPath)) {
    $scriptRoot = if ([string]::IsNullOrWhiteSpace($PSScriptRoot)) {
        (Get-Location).Path
    } else {
        $PSScriptRoot
    }
    $RepoPath = (Resolve-Path (Join-Path $scriptRoot "..\..\..")).Path
}

function Invoke-Wsl {
    param([string]$Cmd)
    wsl -d $Distro -- bash -lc $Cmd
    if ($LASTEXITCODE -ne 0) {
        throw "WSL command failed: $Cmd"
    }
}

function Invoke-GuestPlink {
    param([string]$Cmd)
    $plink = Join-Path $env:ProgramFiles "PuTTY\\plink.exe"
    if (-not (Test-Path $plink)) {
        throw "PuTTY plink not found at '$plink'. Install PuTTY."
    }

    $args = @("-ssh", "-P", "$SshPort", "-l", $VmUser, "-pw", $VmPassword)
    if (-not [string]::IsNullOrWhiteSpace($HostKey)) {
        $args += @("-batch", "-hostkey", $HostKey)
    }
    $args += @("127.0.0.1", $Cmd)
    & $plink @args
    if ($LASTEXITCODE -ne 0) {
        throw "Guest command failed: $Cmd"
    }
}

function Copy-IfNeeded {
    param(
        [string]$Source,
        [string]$Destination
    )

    $sourceFull = [System.IO.Path]::GetFullPath($Source)
    $destinationFull = [System.IO.Path]::GetFullPath($Destination)

    if ($sourceFull -eq $destinationFull) {
        Write-Host "skip_copy source==destination: $destinationFull"
        return
    }

    Copy-Item $sourceFull $destinationFull -Force
}

$repoPathResolved = (Resolve-Path $RepoPath).Path
$repoEscaped = $repoPathResolved.Replace("'", "'""'""'")
$repoWsl = (wsl -d $Distro -- bash -lc "wslpath -a '$repoEscaped'" | Out-String).Trim()
if ([string]::IsNullOrWhiteSpace($repoWsl)) {
    throw "Failed to resolve WSL path for '$repoPathResolved'."
}

$baseWsl = if ($BaseImage.StartsWith("/")) { $BaseImage } else { "$repoWsl/$BaseImage" }
$overlayWsl = if ($OverlayImage.StartsWith("/")) { $OverlayImage } else { "$repoWsl/$OverlayImage" }
$rulesWsl = "$repoWsl/rules"
$samplesWsl = "$repoWsl/samples"
$artifactsWsl = "$repoWsl/artifacts"
$qemuLogWsl = "$repoWsl/vm/qemu.log"

Write-Host "[prepare-dirs]"
Invoke-Wsl "cd '$repoWsl' && mkdir -p samples artifacts pcap vm"

Write-Host "[check-base-image]"
Invoke-Wsl "test -f '$baseWsl'"

if (-not $SkipBuild) {
    Write-Host "[build-agent]"
    Invoke-Wsl "source ~/.cargo/env && cd '$repoWsl' && cargo build --release --bin rtrace-agent"
}

Write-Host "[stage-files]"
$sampleCandidates = @(
    (Join-Path $repoPathResolved "tmp\bins\$SampleBinary"),
    (Join-Path $repoPathResolved "bins\$SampleBinary"),
    (Join-Path $repoPathResolved "tmp\samples\$SampleBinary"),
    (Join-Path $repoPathResolved "samples\$SampleBinary")
)
$agentCandidates = @(
    (Join-Path $repoPathResolved "target\release\rtrace-agent"),
    (Join-Path $repoPathResolved "tmp\samples\rtrace-agent")
)
$sampleSource = $sampleCandidates | Where-Object { Test-Path $_ } | Select-Object -First 1
if (-not $sampleSource) {
    throw "Sample binary '$SampleBinary' not found. Checked: $($sampleCandidates -join ', ')"
}
$agentSource = $agentCandidates | Where-Object { Test-Path $_ } | Select-Object -First 1
if (-not $agentSource) {
    throw "rtrace-agent not found. Checked: $($agentCandidates -join ', ')"
}
Copy-IfNeeded $agentSource (Join-Path $repoPathResolved "samples\rtrace-agent")
Copy-IfNeeded (Join-Path $repoPathResolved "scripts\sandbox\linux\run_agent.sh") (Join-Path $repoPathResolved "samples\run_agent.sh")
Copy-IfNeeded $sampleSource (Join-Path $repoPathResolved "samples\$SampleBinary")

Write-Host "[overlay]"
$overlayInfo = (wsl -d $Distro -- bash -lc "qemu-img info '$overlayWsl' 2>/dev/null | awk -F': ' '/^backing file:/{print `$2; exit}' | sed 's/ (actual path:.*$//' " | Out-String).Trim()
if ([string]::IsNullOrWhiteSpace($overlayInfo)) {
    Invoke-Wsl "qemu-img create -f qcow2 -F qcow2 -b '$baseWsl' '$overlayWsl'"
} else {
    $baseReal = (wsl -d $Distro -- bash -lc "readlink -f '$baseWsl'" | Out-String).Trim()
    $backing = $overlayInfo
    if (-not $backing.StartsWith("/")) {
        $overlayDir = (wsl -d $Distro -- bash -lc "dirname '$overlayWsl'" | Out-String).Trim()
        $backing = "$overlayDir/$backing"
    }
    $backingReal = (wsl -d $Distro -- bash -lc "readlink -f '$backing' 2>/dev/null || true" | Out-String).Trim()
    if ([string]::IsNullOrWhiteSpace($backingReal) -or $backingReal -ne $baseReal) {
        $backup = "$overlayWsl.bak.$([DateTimeOffset]::UtcNow.ToUnixTimeSeconds())"
        Invoke-Wsl "mv '$overlayWsl' '$backup' && qemu-img create -f qcow2 -F qcow2 -b '$baseWsl' '$overlayWsl'"
        Write-Host "overlay_recreated backup=$backup"
    }
}

Write-Host "[start-vm]"
$null = wsl -d $Distro -- bash -lc "rm -f '$qemuLogWsl'"
$kvmArg = ""
if ($UseKvm -eq "on") {
    $kvmArg = "-enable-kvm"
} elseif ($UseKvm -eq "auto") {
    $kvmAvailable = (wsl -d $Distro -- bash -lc "test -e /dev/kvm; echo `$?" | Out-String).Trim() -eq "0"
    if ($kvmAvailable) {
        $kvmArg = "-enable-kvm"
    }
}
$qemuCmd = @"
cd '$repoWsl'
qemu-system-x86_64 $kvmArg \
  -m $MemoryMb \
  -smp $CpuCount \
  -drive file='$overlayWsl',if=virtio,format=qcow2 \
  -netdev user,id=net0,hostfwd=tcp::$SshPort-:22 \
  -device virtio-net-pci,netdev=net0 \
  -virtfs local,path='$rulesWsl',mount_tag=rules,security_model=none,readonly=on \
  -virtfs local,path='$samplesWsl',mount_tag=samples,security_model=none,readonly=on \
  -virtfs local,path='$artifactsWsl',mount_tag=artifacts,security_model=none,readonly=off \
  -display '$DisplayBackend' > '$qemuLogWsl' 2>&1
"@

$vmProc = Start-Process -FilePath "wsl" -ArgumentList @("-d", $Distro, "--", "bash", "-lc", $qemuCmd) -PassThru
Write-Host "vm_process_id=$($vmProc.Id)"

Write-Host "[wait-ssh]"
$deadline = (Get-Date).AddMinutes(3)
$ready = $false
while ((Get-Date) -lt $deadline) {
    $vmProc.Refresh()
    if ($vmProc.HasExited) {
        break
    }
    try {
        $tcp = New-Object System.Net.Sockets.TcpClient
        $iar = $tcp.BeginConnect("127.0.0.1", $SshPort, $null, $null)
        if ($iar.AsyncWaitHandle.WaitOne(700)) {
            $tcp.EndConnect($iar)
            $tcp.Close()
            $ready = $true
            break
        }
        $tcp.Close()
    } catch {
    }
    Start-Sleep -Milliseconds 700
}
if (-not $ready) {
    $qemuLogTail = (wsl -d $Distro -- bash -lc "tail -n 60 '$qemuLogWsl' 2>/dev/null || true" | Out-String).Trim()
    if (-not [string]::IsNullOrWhiteSpace($qemuLogTail)) {
        throw "SSH on 127.0.0.1:$SshPort is not reachable. QEMU log tail:`n$qemuLogTail"
    }
    throw "SSH on 127.0.0.1:$SshPort is not reachable."
}

Write-Host "[mount-shares]"
Invoke-GuestPlink "echo $VmPassword | sudo -S mkdir -p /rules /samples /artifacts"
Invoke-GuestPlink "echo $VmPassword | sudo -S sh -lc 'mountpoint -q /rules || mount -t virtiofs rules /rules 2>/dev/null || mount -t 9p -o trans=virtio,version=9p2000.L,msize=262144,ro rules /rules'"
Invoke-GuestPlink "echo $VmPassword | sudo -S sh -lc 'mountpoint -q /samples || mount -t virtiofs samples /samples 2>/dev/null || mount -t 9p -o trans=virtio,version=9p2000.L,msize=262144,ro samples /samples'"
Invoke-GuestPlink "echo $VmPassword | sudo -S sh -lc 'mountpoint -q /artifacts || mount -t virtiofs artifacts /artifacts 2>/dev/null || mount -t 9p -o trans=virtio,version=9p2000.L,msize=262144,rw artifacts /artifacts'"

Write-Host "[ensure-libyara]"
Invoke-GuestPlink "echo $VmPassword | sudo -S bash -lc 'ldconfig -p | grep -q libyara.so || (apt-get update && apt-get install -y --no-install-recommends libyara10 || apt-get install -y --no-install-recommends libyara9 || true)'"

Write-Host ""
Write-Host "VM is ready."
Write-Host "Inside VM run: /samples/rtrace-agent --help"
Write-Host "Examples:"
Write-Host "  sudo /samples/rtrace-agent --rules-dir /rules --samples-dir /samples --artifacts-dir /artifacts --scan-interval-ms 500 --verbose --stop-on-hit"
Write-Host "  sudo /samples/rtrace-agent --rules-dir /rules --pid 1234 --artifacts-dir /artifacts --stop-on-hit"
Write-Host "  sudo /samples/rtrace-agent --rules-dir /rules --artifacts-dir /artifacts --scan-interval-ms 500 --stop-on-hit"
Write-Host "Then run sample: /samples/$SampleBinary"
