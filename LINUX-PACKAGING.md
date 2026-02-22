# Linux Packaging Guide

Null IDE supports multiple Linux package formats for universal distribution.

## Supported Formats

| Format   | Universal | Sandboxed | Auto-Updates | Compatibility               |
| -------- | --------- | --------- | ------------ | --------------------------- |
| Flatpak  | Yes       | Yes       | Yes          | All distros with Flatpak    |
| Snap     | Yes       | Classic   | Yes          | Ubuntu, derivatives, others |
| AppImage | Yes       | No        | No           | Most distros                |
| DEB      | No        | No        | No           | Debian, Ubuntu, Mint        |
| RPM      | No        | No        | No           | Fedora, RHEL, openSUSE      |

## Flatpak Installation

### Prerequisites

```bash
# Ubuntu/Debian
sudo apt install flatpak flatpak-builder

# Fedora
sudo dnf install flatpak flatpak-builder

# Arch
sudo pacman -S flatpak flatpak-builder
```

### Install Runtimes

```bash
flatpak install -y flathub org.freedesktop.Platform//23.08
flatpak install -y flathub org.freedesktop.Sdk//23.08
```

### Build Flatpak

```bash
npm run package:flatpak
```

### Install

```bash
flatpak install null-ide.flatpak
flatpak run com.nullide.app
```

### Permissions

- Full filesystem access (`--filesystem=host`)
- Network access (`--share=network`)
- X11/Wayland display (`--socket=x11`, `--socket=wayland`)
- Session bus for Discord RPC (`--socket=session-bus`)
- Development mode for terminal (`--allow=devel`)

## Snap Installation

### Prerequisites

```bash
sudo snap install snapcraft --classic
sudo snap install multipass
```

### Build Snap

```bash
npm run package:snap
```

### Install

```bash
sudo snap install --dangerous null-ide_*.snap --classic
null-ide
```

### Confinement

The Snap uses classic confinement which provides full system access. This is required for:

- File system access for code editing
- Terminal emulation with shell access
- Network security tools
- Process spawning for command execution

## AppImage Installation

```bash
chmod +x Null-IDE-3.4.0.AppImage
./Null-IDE-3.4.0.AppImage
```

## DEB Installation

```bash
sudo dpkg -i null-ide_3.4.0_amd64.deb
sudo apt-get install -f
null-ide
```

## RPM Installation

```bash
sudo dnf install null-ide-3.4.0.x86_64.rpm
null-ide
```

## Arch Linux

```bash
git clone https://github.com/4fqr/null-ide.git
cd null-ide
makepkg -si
```

## Build All Packages

```bash
npm run package:linux
```

This generates AppImage, DEB, RPM, Snap, and Flatpak packages.

## Troubleshooting

### Flatpak Permission Denied

```bash
flatpak override --user --filesystem=home com.nullide.app
```

### Snap Not Found

```bash
export PATH=$PATH:/snap/bin
```

### Node.js Version Mismatch

```bash
nvm install 20
nvm use 20
```

### Dependency Conflicts

```bash
rm -rf node_modules package-lock.json
npm install
```

## CI/CD Integration

```yaml
name: Build Linux Packages
on:
  release:
    types: [created]
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      - uses: actions/setup-node@v3
        with:
          node-version: '20'
      - run: npm ci
      - run: npm run package:linux
      - uses: actions/upload-artifact@v3
        with:
          name: linux-packages
          path: release/*
```

## Additional Resources

- [Flatpak Documentation](https://docs.flatpak.org/)
- [Snap Documentation](https://snapcraft.io/docs)
- [Electron Builder](https://www.electron.build/)
- [AppImage](https://docs.appimage.org/)
