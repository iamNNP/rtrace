param(
    [string]$Distro = "Ubuntu",
    [string]$RepoPath = "",
    [string]$BaseImage = "vm/simple_ubuntu.qcow2",
    [string]$BaseImageUrl = ""
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

$repoPathResolved = (Resolve-Path $RepoPath).Path
$repoEscaped = $repoPathResolved.Replace("'", "'""'""'")
$repoWsl = (wsl -d $Distro -- bash -lc "wslpath -a '$repoEscaped'" | Out-String).Trim()
if ([string]::IsNullOrWhiteSpace($repoWsl)) {
    throw "Failed to resolve WSL path for '$repoPathResolved'."
}

$baseWsl = if ($BaseImage.StartsWith("/")) { $BaseImage } else { "$repoWsl/$BaseImage" }

Write-Host "[install-qemu]"
wsl -d $Distro -- bash -lc "sudo apt update && sudo apt install -y qemu-system-x86 qemu-utils qemu-system-gui virtiofsd wget"
if ($LASTEXITCODE -ne 0) {
    throw "Failed to install QEMU packages in WSL."
}

Write-Host "[prepare-dirs]"
wsl -d $Distro -- bash -lc "cd '$repoWsl' && mkdir -p vm samples artifacts pcap rules"
if ($LASTEXITCODE -ne 0) {
    throw "Failed to create project directories."
}

Write-Host "[base-image]"
$hasBase = (wsl -d $Distro -- bash -lc "test -f '$baseWsl'; echo `$?" | Out-String).Trim() -eq "0"
if (-not $hasBase) {
    if ([string]::IsNullOrWhiteSpace($BaseImageUrl)) {
        throw "Base image '$baseWsl' not found. Provide -BaseImageUrl or place qcow2 manually."
    }
    wsl -d $Distro -- bash -lc "mkdir -p '$(Split-Path -Path $baseWsl -Parent)' && wget -O '$baseWsl' '$BaseImageUrl'"
    if ($LASTEXITCODE -ne 0) {
        throw "Failed to download base image from '$BaseImageUrl'."
    }
}

wsl -d $Distro -- bash -lc "qemu-img info '$baseWsl' | sed -n '1,12p'"
Write-Host ""
Write-Host "VM preparation complete."
Write-Host "Base image: $baseWsl"
