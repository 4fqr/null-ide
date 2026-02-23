#!/bin/bash

set -e

APP_ID="com.nullide.app"
APP_NAME="Null IDE"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

log_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

log_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

check_dependencies() {
    log_info "Checking dependencies..."
    
    local missing_deps=()
    
    if ! command -v flatpak &> /dev/null; then
        missing_deps+=("flatpak")
    fi
    
    if ! command -v flatpak-builder &> /dev/null; then
        missing_deps+=("flatpak-builder")
    fi
    
    if ! command -v npm &> /dev/null; then
        missing_deps+=("npm")
    fi
    
    if [ ${#missing_deps[@]} -ne 0 ]; then
        log_error "Missing dependencies: ${missing_deps[*]}"
        echo ""
        echo "Install them with:"
        echo "  Ubuntu/Debian: sudo apt install flatpak flatpak-builder npm"
        echo "  Fedora: sudo dnf install flatpak flatpak-builder npm"
        echo "  Arch: sudo pacman -S flatpak flatpak-builder npm"
        exit 1
    fi
    
    log_success "All dependencies satisfied"
}

setup_flatpak_remote() {
    log_info "Setting up Flathub remote..."
    
    if ! flatpak remotes | grep -q "flathub"; then
        flatpak remote-add --user --if-not-exists flathub https://flathub.org/repo/flathub.flatpakrepo
        log_success "Flathub remote added"
    else
        log_info "Flathub remote already exists"
    fi
}

install_runtime() {
    log_info "Installing required runtimes..."
    
    flatpak install --user -y flathub org.freedesktop.Platform//24.08
    flatpak install --user -y flathub org.freedesktop.Sdk//24.08
    
    log_success "Runtimes installed"
}

build_app() {
    log_info "Building application..."
    
    cd "$PROJECT_ROOT"
    
    log_info "Installing Node.js dependencies..."
    npm install
    
    log_info "Building application with Vite and TypeScript..."
    npm run build
    
    log_success "Application built"
}

build_flatpak() {
    log_info "Building Flatpak package..."
    
    cd "$PROJECT_ROOT"
    
    local BUILD_DIR="${PROJECT_ROOT}/flatpak-build"
    local REPO_DIR="${PROJECT_ROOT}/flatpak-repo"
    
    mkdir -p "$BUILD_DIR"
    mkdir -p "$REPO_DIR"
    
    flatpak-builder \
        --user \
        --install-deps-from=flathub \
        --force-clean \
        --repo="$REPO_DIR" \
        "$BUILD_DIR" \
        "${APP_ID}.json"
    
    log_success "Flatpak built successfully"
}

install_flatpak() {
    log_info "Installing Flatpak locally..."
    
    cd "$PROJECT_ROOT"
    
    flatpak-builder \
        --user \
        --install-deps-from=flathub \
        --force-clean \
        --install \
        "${PROJECT_ROOT}/flatpak-build" \
        "${APP_ID}.json"
    
    log_success "Flatpak installed"
}

create_bundle() {
    log_info "Creating Flatpak bundle..."
    
    cd "$PROJECT_ROOT"
    
    local BUNDLE_FILE="${APP_NAME// /-}-$(node -p "require('./package.json').version").flatpak"
    
    flatpak build-bundle "${PROJECT_ROOT}/flatpak-repo" "$BUNDLE_FILE" "$APP_ID"
    
    log_success "Bundle created: $BUNDLE_FILE"
    echo ""
    echo "To install the bundle:"
    echo "  flatpak install --user $BUNDLE_FILE"
}

clean_build() {
    log_info "Cleaning build artifacts..."
    
    cd "$PROJECT_ROOT"
    
    rm -rf flatpak-build flatpak-repo .flatpak-builder
    
    log_success "Cleaned"
}

run_app() {
    log_info "Running ${APP_NAME}..."
    flatpak run "$APP_ID"
}

show_usage() {
    echo "Usage: $0 [command]"
    echo ""
    echo "Commands:"
    echo "  build       Build the application and Flatpak (default)"
    echo "  install     Build and install Flatpak locally"
    echo "  bundle      Build and create a distributable .flatpak bundle"
    echo "  run         Run the installed Flatpak"
    echo "  clean       Clean build artifacts"
    echo "  all         Build, install, and create bundle"
    echo "  deps        Check and install dependencies only"
    echo "  help        Show this help message"
    echo ""
    echo "Examples:"
    echo "  $0 build          # Build Flatpak"
    echo "  $0 install        # Build and install"
    echo "  $0 bundle         # Create distributable bundle"
    echo "  $0 all            # Full build process"
}

main() {
    local command="${1:-build}"
    
    echo ""
    echo "========================================"
    echo "  ${APP_NAME} Flatpak Builder"
    echo "========================================"
    echo ""
    
    case "$command" in
        build)
            check_dependencies
            setup_flatpak_remote
            build_app
            build_flatpak
            log_success "Build complete!"
            ;;
        install)
            check_dependencies
            setup_flatpak_remote
            build_app
            install_flatpak
            log_success "Installation complete!"
            echo "Run with: flatpak run $APP_ID"
            ;;
        bundle)
            check_dependencies
            setup_flatpak_remote
            build_app
            build_flatpak
            create_bundle
            ;;
        run)
            run_app
            ;;
        clean)
            clean_build
            ;;
        all)
            check_dependencies
            setup_flatpak_remote
            install_runtime
            build_app
            build_flatpak
            install_flatpak
            create_bundle
            log_success "Complete! Flatpak is ready for distribution."
            ;;
        deps)
            check_dependencies
            setup_flatpak_remote
            install_runtime
            ;;
        help|--help|-h)
            show_usage
            ;;
        *)
            log_error "Unknown command: $command"
            show_usage
            exit 1
            ;;
    esac
}

main "$@"
