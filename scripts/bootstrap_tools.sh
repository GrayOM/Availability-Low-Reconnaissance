#!/usr/bin/env bash
# scripts/bootstrap_tools.sh
# ===========================
# Install required reconnaissance tools into project-local .tools/bin
# Does NOT modify ~/.bashrc, ~/.zshrc, or any shell profile.
#
# Passive pipeline (default): subfinder
# Active verification (--enable-active-verify): dnsx, httpx, naabu
# wappalyzer: removed from MVP pipeline
#
# Usage:
#   bash ./scripts/bootstrap_tools.sh

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
LOCAL_BIN="${PROJECT_ROOT}/.tools/bin"

GREEN='\033[0;32m'; YELLOW='\033[1;33m'; RED='\033[0;31m'; NC='\033[0m'
info()    { echo -e "${GREEN}[INFO]${NC}  $*"; }
warn()    { echo -e "${YELLOW}[WARN]${NC}  $*"; }
error()   { echo -e "${RED}[ERROR]${NC} $*" >&2; }
success() { echo -e "${GREEN}[OK]${NC}    $*"; }

echo ""
echo "======================================================"
echo "  ALR — Bootstrap Tool Installer"
echo "  Project root : ${PROJECT_ROOT}"
echo "  Install dir  : ${LOCAL_BIN}"
echo "======================================================"
echo ""

# Check Go
if ! command -v go &>/dev/null; then
  error "Go is not installed or not on PATH."
  echo "  Install Go from: https://go.dev/dl/"
  exit 1
fi
info "Go found: $(go version | awk '{print $3}')"

mkdir -p "${LOCAL_BIN}"
info "Local bin dir ready: ${LOCAL_BIN}"

export GOBIN="${LOCAL_BIN}"

TOOLS=(
  "github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest"
  "github.com/projectdiscovery/dnsx/cmd/dnsx@latest"
  "github.com/projectdiscovery/httpx/cmd/httpx@latest"
  "github.com/projectdiscovery/naabu/v2/cmd/naabu@latest"
)
TOOL_NAMES=("subfinder" "dnsx" "httpx" "naabu")

echo ""
info "Installing passive + active tools into ${LOCAL_BIN} ..."
info "(Only subfinder is needed for the default passive-only pipeline)"
echo ""

for i in "${!TOOLS[@]}"; do
  NAME="${TOOL_NAMES[$i]}"
  PKG="${TOOLS[$i]}"
  echo "  → Installing ${NAME} ..."
  if go install "${PKG}"; then
    success "${NAME} installed"
  else
    error "Failed to install ${NAME}"
    echo "  Manual: GOBIN=${LOCAL_BIN} go install ${PKG}"
  fi
done

echo ""
echo "======================================================"
echo "  Installation Complete"
echo "======================================================"
echo ""
for TOOL in "${TOOL_NAMES[@]}"; do
  if [ -f "${LOCAL_BIN}/${TOOL}" ] && [ -x "${LOCAL_BIN}/${TOOL}" ]; then
    echo "  [OK]  ${TOOL} -> ${LOCAL_BIN}/${TOOL}"
  else
    echo "  [--]  ${TOOL} -> not found"
  fi
done

echo ""
info "Verify with:  python3 -m cli.main --doctor"
info "Then run:     python3 -m cli.main --domain example.com"
echo ""
