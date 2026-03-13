# scripts/bootstrap_tools.ps1
# ============================
# Install required reconnaissance tools into project-local .tools\bin
# Does NOT modify PATH permanently or any user profile.
#
# Usage (run from project root):
#   .\scripts\bootstrap_tools.ps1
#
# Requirements:
#   - Go 1.19+ (https://go.dev/dl/)
#   - PowerShell 5+ or PowerShell Core 7+

$ErrorActionPreference = "Stop"

# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------
$ScriptDir   = Split-Path -Parent $MyInvocation.MyCommand.Path
$ProjectRoot = Split-Path -Parent $ScriptDir
$LocalBin    = Join-Path $ProjectRoot ".tools\bin"

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
function Info    { param($msg) Write-Host "[INFO]  $msg" -ForegroundColor Cyan    }
function Warn    { param($msg) Write-Host "[WARN]  $msg" -ForegroundColor Yellow  }
function Success { param($msg) Write-Host "[OK]    $msg" -ForegroundColor Green   }
function Err     { param($msg) Write-Host "[ERROR] $msg" -ForegroundColor Red     }

# ---------------------------------------------------------------------------
# Banner
# ---------------------------------------------------------------------------
Write-Host ""
Write-Host "======================================================" -ForegroundColor Cyan
Write-Host "  ALR — Bootstrap Tool Installer (Windows/PowerShell)"
Write-Host "  Project root : $ProjectRoot"
Write-Host "  Install dir  : $LocalBin"
Write-Host "======================================================" -ForegroundColor Cyan
Write-Host ""

# ---------------------------------------------------------------------------
# Check Go
# ---------------------------------------------------------------------------
try {
    $goVersion = (& go version 2>&1)
    Info "Go found: $goVersion"
} catch {
    Err "Go is not installed or not on PATH."
    Write-Host ""
    Write-Host "  Install Go from: https://go.dev/dl/"
    Write-Host "  Then re-run this script."
    Write-Host ""
    exit 1
}

# ---------------------------------------------------------------------------
# Create local bin directory
# ---------------------------------------------------------------------------
if (-not (Test-Path $LocalBin)) {
    New-Item -ItemType Directory -Path $LocalBin -Force | Out-Null
}
Info "Local bin dir ready: $LocalBin"

# ---------------------------------------------------------------------------
# Set GOBIN and install tools
# ---------------------------------------------------------------------------
$env:GOBIN = $LocalBin

$tools = @(
    @{ Name = "subfinder"; Pkg = "github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest" },
    @{ Name = "dnsx";      Pkg = "github.com/projectdiscovery/dnsx/cmd/dnsx@latest"              },
    @{ Name = "httpx";     Pkg = "github.com/projectdiscovery/httpx/cmd/httpx@latest"            },
    @{ Name = "naabu";     Pkg = "github.com/projectdiscovery/naabu/v2/cmd/naabu@latest"         }
)

Write-Host ""
Info "Installing required tools into $LocalBin ..."
Write-Host ""

foreach ($tool in $tools) {
    Write-Host "  -> Installing $($tool.Name) ..."
    try {
        & go install $tool.Pkg
        Success "$($tool.Name) installed"
    } catch {
        Err "Failed to install $($tool.Name)"
        Write-Host "  Try manually: `$env:GOBIN='$LocalBin'; go install $($tool.Pkg)"
    }
}

# ---------------------------------------------------------------------------
# ---------------------------------------------------------------------------
Write-Host ""
$npmAvailable = $null
try { $npmAvailable = & npm --version 2>&1 } catch {}

if ($npmAvailable) {
    $nodeModulesDir = Join-Path $ProjectRoot ".tools"
    try {
    } catch {
    }
} else {
}

# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------
Write-Host ""
Write-Host "======================================================" -ForegroundColor Cyan
Write-Host "  Installation Complete — Tool Summary"
Write-Host "======================================================" -ForegroundColor Cyan
Write-Host ""

foreach ($t in $allTools) {
    $p = Join-Path $LocalBin "$t.exe"
    $p2 = Join-Path $LocalBin $t
    if ((Test-Path $p) -or (Test-Path $p2)) {
        Write-Host "  [OK]  $t -> $LocalBin" -ForegroundColor Green
    } else {
        Write-Host "  [--]  $t -> not found" -ForegroundColor DarkGray
    }
}

Write-Host ""
Info "Verify your setup with:"
Write-Host ""
Write-Host "    python -m cli.main --doctor"
Write-Host ""
Write-Host "Then run a real assessment:"
Write-Host ""
Write-Host "    python -m cli.main --domain example.com"
Write-Host ""
Write-Host "======================================================" -ForegroundColor Cyan
Write-Host ""
