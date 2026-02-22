#!/bin/bash

set -e

GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'

echo -e "${BLUE}Building Null IDE for Linux...${NC}"

BUILD_TYPE="${1:-all}"

if [ ! -d "node_modules" ]; then
    echo -e "${YELLOW}Installing dependencies...${NC}"
    npm install
fi

echo -e "${YELLOW}Building application...${NC}"
npm run build

build_standard() {
    echo -e "${BLUE}Creating standard Linux installers (AppImage, DEB, RPM)...${NC}"
    npx electron-builder --linux
    echo -e "${GREEN}Standard packages built successfully!${NC}"
}

build_snap() {
    echo -e "${BLUE}Creating Snap package...${NC}"
    
    if ! command -v snapcraft &> /dev/null; then
        echo -e "${RED}snapcraft is not installed. Install it with: sudo snap install snapcraft --classic${NC}"
        return 1
    fi
    
    snapcraft clean
    snapcraft
    
    echo -e "${GREEN}Snap package built successfully!${NC}"
    echo -e "${YELLOW}To install locally: sudo snap install --dangerous null-ide_*.snap --classic${NC}"
}

build_flatpak() {
    echo -e "${BLUE}Creating Flatpak package...${NC}"
    
    if ! command -v flatpak-builder &> /dev/null; then
        echo -e "${RED}flatpak-builder is not installed. Install it with: sudo apt install flatpak-builder${NC}"
        return 1
    fi
    
    if ! flatpak list --runtime | grep -q "org.freedesktop.Platform.*23.08"; then
        echo -e "${YELLOW}Installing required Flatpak runtime...${NC}"
        flatpak install -y flathub org.freedesktop.Platform//23.08
        flatpak install -y flathub org.freedesktop.Sdk//23.08
        flatpak install -y flathub org.electronjs.Electron2.BaseApp//23.08
    fi
    
    if command -v flatpak-node-generator &> /dev/null; then
        echo -e "${YELLOW}Generating npm dependencies manifest...${NC}"
        flatpak-node-generator npm package-lock.json -o generated-sources.json
    else
        echo -e "${YELLOW}flatpak-node-generator not found. You may need to manually create generated-sources.json${NC}"
        echo -e "${YELLOW}Install it from: https://github.com/flatpak/flatpak-builder-tools${NC}"
        echo '[]' > generated-sources.json
    fi
    
    mkdir -p build/flatpak
    flatpak-builder --force-clean --repo=build/flatpak/repo build/flatpak/build com.nullsec.NullIDE.yaml
    
    flatpak build-bundle build/flatpak/repo release/null-ide.flatpak com.nullsec.NullIDE
    
    echo -e "${GREEN}Flatpak package built successfully!${NC}"
    echo -e "${YELLOW}To install locally: flatpak install null-ide.flatpak${NC}"
}

case "$BUILD_TYPE" in
    all)
        build_standard
        echo ""
        echo -e "${BLUE}Building universal packages...${NC}"
        build_snap || echo -e "${YELLOW}Snap build failed or skipped${NC}"
        build_flatpak || echo -e "${YELLOW}Flatpak build failed or skipped${NC}"
        ;;
    standard)
        build_standard
        ;;
    snap)
        build_snap
        ;;
    flatpak)
        build_flatpak
        ;;
    *)
        echo -e "${RED}Invalid build type: $BUILD_TYPE${NC}"
        echo "Usage: $0 [all|standard|snap|flatpak]"
        echo "  all      - Build all package types (default)"
        echo "  standard - Build AppImage, DEB, RPM only"
        echo "  snap     - Build Snap package only"
        echo "  flatpak  - Build Flatpak package only"
        exit 1
        ;;
esac

echo ""
echo -e "${GREEN}Build complete! Check the release/ directory for installers:${NC}"
ls -lh release/*.{AppImage,deb,rpm,snap,flatpak} 2>/dev/null || echo "Some package types may not have been built"
echo ""
echo -e "${BLUE}Installation instructions:${NC}"
echo -e "  ${YELLOW}AppImage:${NC} chmod +x null-ide-*.AppImage && ./null-ide-*.AppImage"
echo -e "  ${YELLOW}DEB:${NC}      sudo dpkg -i null-ide_*.deb"
echo -e "  ${YELLOW}RPM:${NC}      sudo rpm -i null-ide-*.rpm"
echo -e "  ${YELLOW}Snap:${NC}     sudo snap install --dangerous null-ide_*.snap --classic"
echo -e "  ${YELLOW}Flatpak:${NC}  flatpak install null-ide.flatpak"
