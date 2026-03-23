#!/bin/bash
# Boson Infinity — Release Build Script
# Builds all binaries for Windows, Linux, macOS (amd64 + arm64)

set -e

VERSION="2.1.0"
MODULE="github.com/IronBamBam1990/BoSon-Infinity"
LDFLAGS="-s -w -X main.version=${VERSION}"
DIST="dist"
BINARIES=(
    "cmd/node:boson-node"
    "cmd/cli:boson-cli"
    "cmd/miner:boson-miner"
    "cmd/oracle:boson-oracle"
)
WALLET_PKG="cmd/wallet:boson-wallet"

rm -rf "${DIST}"
mkdir -p "${DIST}"

# Platforms: OS/ARCH
PLATFORMS=(
    "windows/amd64"
    "linux/amd64"
    "linux/arm64"
    "darwin/amd64"
    "darwin/arm64"
)

echo "=== Boson Infinity v${VERSION} — Release Build ==="
echo ""

for platform in "${PLATFORMS[@]}"; do
    IFS='/' read -r GOOS GOARCH <<< "$platform"
    EXT=""
    if [ "$GOOS" = "windows" ]; then EXT=".exe"; fi

    DIR="${DIST}/boson-infinity-${VERSION}-${GOOS}-${GOARCH}"
    mkdir -p "${DIR}"

    echo "Building ${GOOS}/${GOARCH}..."

    for entry in "${BINARIES[@]}"; do
        IFS=':' read -r pkg name <<< "$entry"
        echo "  ${name}${EXT}"
        CGO_ENABLED=0 GOOS=$GOOS GOARCH=$GOARCH \
            go build -ldflags="${LDFLAGS}" -o "${DIR}/${name}${EXT}" "./${pkg}/"
    done

    # Wallet (with build tag)
    IFS=':' read -r pkg name <<< "$WALLET_PKG"
    echo "  ${name}${EXT}"
    CGO_ENABLED=0 GOOS=$GOOS GOARCH=$GOARCH \
        go build -tags wallet -ldflags="${LDFLAGS}" -o "${DIR}/${name}${EXT}" "./${pkg}/"

    # Copy config files
    cp boson.env.example "${DIR}/"
    cp README.md "${DIR}/"
    cp LICENSE "${DIR}/" 2>/dev/null || true

    # Create archive
    cd "${DIST}"
    ARCHIVE="boson-infinity-${VERSION}-${GOOS}-${GOARCH}"
    if [ "$GOOS" = "windows" ]; then
        zip -q -r "${ARCHIVE}.zip" "${ARCHIVE}/"
        echo "  → ${ARCHIVE}.zip"
    else
        tar czf "${ARCHIVE}.tar.gz" "${ARCHIVE}/"
        echo "  → ${ARCHIVE}.tar.gz"
    fi
    cd ..

    echo ""
done

echo "=== Release build complete ==="
echo ""
ls -lh "${DIST}"/*.{zip,tar.gz} 2>/dev/null
