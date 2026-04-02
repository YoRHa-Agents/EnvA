#!/usr/bin/env bash
# Enva installer -- downloads the correct binary for your platform.
#
# Usage:
#   curl -fsSL https://raw.githubusercontent.com/YoRHa-Agents/EnvA/main/scripts/install.sh | bash
#   # or
#   bash install.sh

set -euo pipefail

REPO="YoRHa-Agents/EnvA"
INSTALL_DIR="${INSTALL_DIR:-$HOME/.local/bin}"
BINARY_NAME="enva"
POST_INSTALL_HOOK="${ENVA_POST_INSTALL_HOOK:-${RWC_POST_INSTALL_HOOK:-}}"

run_default_post_install_smoke() {
    local binary_path
    binary_path="$1"

    echo "Running self-test..."
    "$binary_path" vault self-test
    "$binary_path" update --help >/dev/null
}

run_post_install_hook() {
    local binary_path asset_name
    binary_path="$1"
    asset_name="$2"

    if [[ -z "$POST_INSTALL_HOOK" ]]; then
        run_default_post_install_smoke "$binary_path"
        return
    fi

    echo "Running post-install hook..."
    env \
        ENVA_INSTALLED_BINARY="$binary_path" \
        ENVA_INSTALL_ASSET="$asset_name" \
        ENVA_INSTALL_DIR="$INSTALL_DIR" \
        RWC_INSTALLED_BINARY="$binary_path" \
        RWC_INSTALL_ASSET="$asset_name" \
        RWC_INSTALL_DIR="$INSTALL_DIR" \
        bash -lc "$POST_INSTALL_HOOK"
}

detect_platform() {
    local os arch
    os="$(uname -s)"
    arch="$(uname -m)"

    case "$os" in
        Linux)
            case "$arch" in
                x86_64) echo "enva-linux-x86_64" ;;
                aarch64|arm64) echo "enva-linux-aarch64" ;;
                *) echo "Unsupported Linux architecture: $arch" >&2; exit 1 ;;
            esac
            ;;
        Darwin)
            case "$arch" in
                arm64|aarch64) echo "enva-macos-aarch64" ;;
                *) echo "Unsupported macOS architecture: $arch (only Apple Silicon is supported)" >&2; exit 1 ;;
            esac
            ;;
        *) echo "Unsupported OS: $os" >&2; exit 1 ;;
    esac
}

main() {
    local asset
    asset="$(detect_platform)"

    echo "Detected platform: $asset"
    echo "Install directory: $INSTALL_DIR"

    mkdir -p "$INSTALL_DIR"

    if command -v gh >/dev/null 2>&1; then
        echo "Downloading via gh CLI..."
        gh release download --repo "$REPO" --pattern "$asset" --dir "$INSTALL_DIR" --clobber
        mv "$INSTALL_DIR/$asset" "$INSTALL_DIR/$BINARY_NAME"
    else
        local url
        url="https://github.com/$REPO/releases/latest/download/$asset"
        echo "Downloading from $url ..."
        curl -fsSL "$url" -o "$INSTALL_DIR/$BINARY_NAME"
    fi

    chmod +x "$INSTALL_DIR/$BINARY_NAME"

    if [ "$(uname -s)" = "Darwin" ]; then
        xattr -d com.apple.quarantine "$INSTALL_DIR/$BINARY_NAME" 2>/dev/null || true
        codesign -s - "$INSTALL_DIR/$BINARY_NAME" 2>/dev/null || true
    fi

    echo ""
    echo "Installed: $INSTALL_DIR/$BINARY_NAME"
    echo ""

    if ! echo "$PATH" | tr ':' '\n' | grep -qx "$INSTALL_DIR"; then
        echo "Add to your PATH:"
        echo "  export PATH=\"$INSTALL_DIR:\$PATH\""
        echo ""
    fi

    run_post_install_hook "$INSTALL_DIR/$BINARY_NAME" "$asset"
    echo ""
    echo "Installation complete. Run 'enva --help' to get started."
}

main "$@"
