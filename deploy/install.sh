#!/usr/bin/env bash
# Aegis installer: virtualenv, dependencies, Trivy, config scaffold, verification.
#
#   ./deploy/install.sh                 # install into ./.venv
#   PREFIX=/opt/aegis ./deploy/install.sh
#   SKIP_TRIVY=1 ./deploy/install.sh    # Trivy already managed elsewhere
set -euo pipefail

TRIVY_VERSION="${TRIVY_VERSION:-0.76.1}"
PREFIX="${PREFIX:-$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)}"
VENV="${VENV:-$PREFIX/.venv}"
SKIP_TRIVY="${SKIP_TRIVY:-0}"

red()  { printf '\033[31m%s\033[0m\n' "$*"; }
green(){ printf '\033[32m%s\033[0m\n' "$*"; }
info() { printf '\033[1m==>\033[0m %s\n' "$*"; }

trap 'red "install failed on line $LINENO"' ERR

info "Installing Aegis into $PREFIX"

# --- Python -----------------------------------------------------------------
command -v python3 >/dev/null 2>&1 || { red "python3 is required"; exit 1; }
PY_OK=$(python3 -c 'import sys; print(1 if sys.version_info >= (3,10) else 0)')
[ "$PY_OK" = "1" ] || { red "Python 3.10+ is required (found $(python3 -V))"; exit 1; }

info "Creating virtualenv at $VENV"
python3 -m venv "$VENV"
"$VENV/bin/pip" install --quiet --upgrade pip
"$VENV/bin/pip" install --quiet -e "$PREFIX"

# --- Trivy ------------------------------------------------------------------
if [ "$SKIP_TRIVY" = "1" ]; then
  info "Skipping Trivy install (SKIP_TRIVY=1)"
elif command -v trivy >/dev/null 2>&1; then
  info "Trivy already present: $(trivy --version | head -1)"
else
  info "Installing Trivy v$TRIVY_VERSION"
  if command -v brew >/dev/null 2>&1; then
    brew install trivy
  else
    # Installed into the prefix rather than /usr/local so no sudo is needed.
    mkdir -p "$PREFIX/bin"
    curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh \
      | sh -s -- -b "$PREFIX/bin" "v$TRIVY_VERSION"
    export PATH="$PREFIX/bin:$PATH"
    green "Trivy installed to $PREFIX/bin — add it to PATH:"
    echo "    export PATH=\"$PREFIX/bin:\$PATH\""
  fi
fi

# --- Config scaffold --------------------------------------------------------
if [ ! -f "$PREFIX/aegis.yml" ]; then
  info "Writing a starter aegis.yml"
  cp "$PREFIX/examples/aegis.full.yml" "$PREFIX/aegis.yml"
fi
if [ ! -f "$PREFIX/exceptions.yml" ]; then
  printf 'version: 1\nexceptions: []\n' > "$PREFIX/exceptions.yml"
fi
mkdir -p "$PREFIX/reports"

# --- Verify -----------------------------------------------------------------
info "Verifying the installation"
if "$VENV/bin/aegis" doctor; then
  green ""
  green "Aegis is installed."
  echo "  Scan:      $VENV/bin/aegis scan python:3.12-slim"
  echo "  Dashboard: $VENV/bin/aegis serve"
  echo "  Docs:      $PREFIX/docs/USAGE.md"
else
  red ""
  red "Installed, but 'aegis doctor' reported a problem — see above."
  echo "  Troubleshooting: $PREFIX/docs/TROUBLESHOOTING.md"
  exit 1
fi
