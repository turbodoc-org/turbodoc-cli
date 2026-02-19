#!/usr/bin/env bash
set -euo pipefail

REPO="turbodoc-org/turbodoc-cli"

if [[ -z "${BIN_DIR:-}" ]]; then
  if [[ -w "/usr/local/bin" ]]; then
    BIN_DIR="/usr/local/bin"
  else
    BIN_DIR="${HOME}/.local/bin"
  fi
fi

OS="$(uname -s)"
ARCH="$(uname -m)"

case "${OS}-${ARCH}" in
  Linux-aarch64|Linux-arm64)
    TARGET="aarch64-unknown-linux-gnu"
    ARCHIVE_EXT="tar.gz"
    ;;
  Darwin-arm64)
    TARGET="aarch64-apple-darwin"
    ARCHIVE_EXT="tar.gz"
    ;;
  *)
    echo "Unsupported platform: ${OS}-${ARCH}" >&2
    exit 1
    ;;
esac

VERSION="${VERSION:-}"
if [[ -z "${VERSION}" ]]; then
  VERSION="$(
    curl -fsSL "https://api.github.com/repos/${REPO}/releases/latest" \
      | sed -n 's/.*"tag_name": "\([^"]*\)".*/\1/p' \
      | head -n 1
  )"
fi

if [[ -z "${VERSION}" ]]; then
  echo "Failed to determine latest version." >&2
  exit 1
fi

ARCHIVE_NAME="turbodoc-${VERSION}-${TARGET}.${ARCHIVE_EXT}"
DOWNLOAD_URL="https://github.com/${REPO}/releases/download/${VERSION}/${ARCHIVE_NAME}"

TMP_DIR="$(mktemp -d)"
cleanup() {
  rm -rf "${TMP_DIR}"
}
trap cleanup EXIT

echo "Downloading ${ARCHIVE_NAME}..."
curl -fsSL "${DOWNLOAD_URL}" -o "${TMP_DIR}/${ARCHIVE_NAME}"

mkdir -p "${BIN_DIR}"
tar -xzf "${TMP_DIR}/${ARCHIVE_NAME}" -C "${TMP_DIR}"

INSTALL_ROOT="${TMP_DIR}/turbodoc-${VERSION}-${TARGET}"
install -m 0755 "${INSTALL_ROOT}/turbodoc" "${BIN_DIR}/turbodoc"
install -m 0755 "${INSTALL_ROOT}/td" "${BIN_DIR}/td"

echo "Installed turbodoc to ${BIN_DIR}."
echo "Ensure ${BIN_DIR} is on your PATH."
