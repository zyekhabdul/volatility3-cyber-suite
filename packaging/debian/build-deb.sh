#!/usr/bin/env bash
set -euo pipefail

PKG_NAME="vol3-suite"
PKG_VER="2.0.0"
PKG_ARCH="all"
DIST_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
WORK_DIR="$DIST_DIR/build_deb/${PKG_NAME}_${PKG_VER}_${PKG_ARCH}"

echo "==> Building Debian (.deb) package for $PKG_NAME v$PKG_VER..."
rm -rf "$DIST_DIR/build_deb"
mkdir -p "$WORK_DIR/DEBIAN"
mkdir -p "$WORK_DIR/usr/bin"
mkdir -p "$WORK_DIR/usr/lib/python3/dist-packages"
mkdir -p "$WORK_DIR/usr/share/doc/$PKG_NAME"

cat << 'EOF' > "$WORK_DIR/DEBIAN/control"
Package: vol3-suite
Version: 2.0.0
Section: utils
Priority: optional
Architecture: all
Depends: python3 (>= 3.8)
Maintainer: zyekhabdul <zyekhabdulqadirjailani@gmail.com>
Description: Unified Memory Forensics, eBPF Rootkit Detection, and AI-Driven Incident Triage Suite
 Lightweight, modular memory forensics & incident response CLI with eBPF detection
 and automated triage capabilities.
 Includes aliases: vol-ai-triage, ebpf-detector.
EOF

PROJECT_ROOT="$(cd "$DIST_DIR/../.." && pwd)"
cp -r "$PROJECT_ROOT/vol3_suite" "$WORK_DIR/usr/lib/python3/dist-packages/"

cat << 'EOF' > "$WORK_DIR/usr/bin/vol3-suite"
#!/usr/bin/env python3
import sys
from vol3_suite.cli import main
if __name__ == '__main__':
    sys.exit(main())
EOF

cat << 'EOF' > "$WORK_DIR/usr/bin/ebpf-detector"
#!/usr/bin/env python3
import sys
from vol3_suite.cli import main_ebpf
if __name__ == '__main__':
    sys.exit(main_ebpf())
EOF

chmod 755 "$WORK_DIR/usr/bin/vol3-suite" "$WORK_DIR/usr/bin/ebpf-detector"
ln -sf vol3-suite "$WORK_DIR/usr/bin/vol-ai-triage"

cp "$PROJECT_ROOT/README.md" "$WORK_DIR/usr/share/doc/$PKG_NAME/"
cp "$PROJECT_ROOT/LICENSE" "$WORK_DIR/usr/share/doc/$PKG_NAME/copyright"

dpkg-deb --build --root-owner-group "$WORK_DIR" "$DIST_DIR/${PKG_NAME}_${PKG_VER}_${PKG_ARCH}.deb"
rm -rf "$DIST_DIR/build_deb"

echo "==> Done! Created: $DIST_DIR/${PKG_NAME}_${PKG_VER}_${PKG_ARCH}.deb"
