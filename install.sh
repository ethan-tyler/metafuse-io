#!/usr/bin/env bash
#
# MetaFuse Installation Script
#
# Install MetaFuse CLI and API binaries from GitHub releases.
#
# Usage:
#   curl -fsSL https://raw.githubusercontent.com/ethan-tyler/MetaFuse/main/install.sh | bash
#   # or with specific version:
#   curl -fsSL https://raw.githubusercontent.com/ethan-tyler/MetaFuse/main/install.sh | bash -s -- v0.2.0
#

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Configuration
REPO="ethan-tyler/MetaFuse"
INSTALL_DIR="${METAFUSE_INSTALL_DIR:-$HOME/.metafuse/bin}"
VERSION="${1:-latest}"

# Detect platform
detect_platform() {
    local os
    local arch

    # Detect OS
    case "$(uname -s)" in
        Linux*)     os="unknown-linux-gnu";;
        Darwin*)    os="apple-darwin";;
        *)
            echo -e "${RED}Error: Unsupported operating system$(NC)"
            exit 1
            ;;
    esac

    # Detect architecture
    case "$(uname -m)" in
        x86_64)     arch="x86_64";;
        aarch64|arm64) arch="aarch64";;
        *)
            echo -e "${RED}Error: Unsupported architecture$(NC)"
            exit 1
            ;;
    esac

    echo "${arch}-${os}"
}

# Get latest version from GitHub
get_latest_version() {
    curl -fsSL "https://api.github.com/repos/${REPO}/releases/latest" \
        | grep '"tag_name":' \
        | sed -E 's/.*"([^"]+)".*/\1/'
}

# Download and install
install_metafuse() {
    local platform
    local version
    local download_url
    local checksum_url
    local temp_dir

    platform=$(detect_platform)
    echo -e "${GREEN}Detected platform: ${platform}${NC}"

    # Get version
    if [ "$VERSION" = "latest" ]; then
        echo -e "${YELLOW}Fetching latest version...${NC}"
        version=$(get_latest_version)
    else
        version="$VERSION"
    fi

    if [ -z "$version" ]; then
        echo -e "${RED}Error: Could not determine version to install${NC}"
        exit 1
    fi

    echo -e "${GREEN}Installing MetaFuse ${version}${NC}"

    # Construct download URLs
    local tarball="metafuse-${version}-${platform}.tar.gz"
    download_url="https://github.com/${REPO}/releases/download/${version}/${tarball}"
    checksum_url="${download_url}.sha256"

    # Create temp directory
    temp_dir=$(mktemp -d)
    trap "rm -rf ${temp_dir}" EXIT

    echo -e "${YELLOW}Downloading from ${download_url}${NC}"

    # Download tarball
    if ! curl -fsSL "$download_url" -o "${temp_dir}/${tarball}"; then
        echo -e "${RED}Error: Failed to download MetaFuse${NC}"
        echo -e "${RED}URL: ${download_url}${NC}"
        exit 1
    fi

    # Download and verify checksum
    echo -e "${YELLOW}Verifying checksum...${NC}"
    if curl -fsSL "$checksum_url" -o "${temp_dir}/${tarball}.sha256"; then
        cd "${temp_dir}"
        if command -v shasum > /dev/null 2>&1; then
            shasum -a 256 -c "${tarball}.sha256" || {
                echo -e "${RED}Error: Checksum verification failed${NC}"
                exit 1
            }
        else
            echo -e "${YELLOW}Warning: shasum not found, skipping checksum verification${NC}"
        fi
        cd - > /dev/null
    else
        echo -e "${YELLOW}Warning: Could not download checksum, skipping verification${NC}"
    fi

    # Extract tarball
    echo -e "${YELLOW}Extracting binaries...${NC}"
    tar xzf "${temp_dir}/${tarball}" -C "${temp_dir}"

    # Create install directory
    mkdir -p "$INSTALL_DIR"

    # Install binaries
    echo -e "${YELLOW}Installing to ${INSTALL_DIR}${NC}"
    mv "${temp_dir}/metafuse" "$INSTALL_DIR/"
    mv "${temp_dir}/metafuse-api" "$INSTALL_DIR/"
    chmod +x "$INSTALL_DIR/metafuse" "$INSTALL_DIR/metafuse-api"

    echo -e "${GREEN}✓ MetaFuse ${version} installed successfully!${NC}"
    echo ""
    echo -e "${GREEN}Binaries installed to: ${INSTALL_DIR}${NC}"
    echo ""

    # Check if install dir is in PATH
    if [[ ":$PATH:" != *":$INSTALL_DIR:"* ]]; then
        echo -e "${YELLOW}Note: ${INSTALL_DIR} is not in your PATH${NC}"
        echo ""
        echo "Add the following to your shell profile (~/.bashrc, ~/.zshrc, etc.):"
        echo ""
        echo "    export PATH=\"\$PATH:$INSTALL_DIR\""
        echo ""
    fi

    # Verify installation
    echo "Verifying installation:"
    "$INSTALL_DIR/metafuse" --version || true
    echo ""

    echo -e "${GREEN}Get started:${NC}"
    echo "    metafuse init                    # Initialize a new catalog"
    echo "    metafuse-api                     # Start the API server"
    echo ""
    echo "Documentation: https://github.com/${REPO}"
}

# Main
main() {
    echo "MetaFuse Installer"
    echo "=================="
    echo ""

    # Check for required tools
    for tool in curl tar; do
        if ! command -v $tool > /dev/null 2>&1; then
            echo -e "${RED}Error: $tool is required but not installed${NC}"
            exit 1
        fi
    done

    install_metafuse
}

main "$@"
