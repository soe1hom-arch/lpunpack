# lpunpack

Extract partitions from Android super images — written in Go.

[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](LICENSE)
[![build](https://github.com/soe1hom-arch/lpunpack/actions/workflows/build.yml/badge.svg)](https://github.com/soe1hom-arch/lpunpack/actions/workflows/build.yml)

## Overview

`lpunpack` extracts logical partition images (`system.img`, `vendor.img`, `product.img`, etc.)
from Android super images (super.img). It is a pure Go implementation based on the official
[AOSP liblp format](https://android.googlesource.com/platform/system/core/+/refs/heads/main/fs_mgr/liblp/).

Supports Android 10+ super partition format (LP metadata v10.x).

## Usage

```bash
lpunpack [-v] <super_image> [output_directory]
```

### Examples

```bash
# Extract all partitions to current directory
lpunpack super.img

# Extract to specific output directory
lpunpack super.img output/

# Verbose mode (shows geometry and metadata info)
lpunpack -v super.img output/
```

### Options

| Flag | Description |
|------|-------------|
| `-v`, `--verbose` | Show detailed parsing and extraction info |

## Installation

### From source (requires Go 1.22+)

```bash
git clone https://github.com/soe1hom-arch/lpunpack.git
cd lpunpack
go build -o lpunpack .
```

### Cross-compile for other platforms

```bash
# Linux ARM64 (Android Termux)
GOOS=linux GOARCH=arm64 CGO_ENABLED=0 go build -o lpunpack .

# Linux AMD64
GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -o lpunpack .

# macOS (Intel/Apple Silicon)
GOOS=darwin GOARCH=amd64 CGO_ENABLED=0 go build -o lpunpack .
GOOS=darwin GOARCH=arm64 CGO_ENABLED=0 go build -o lpunpack .

# Windows
GOOS=windows GOARCH=amd64 CGO_ENABLED=0 go build -o lpunpack.exe .
```

### Pre-built binaries

Pre-built binaries for Linux, macOS, and Windows (amd64 + arm64) are available on the
[Releases page](https://github.com/soe1hom-arch/lpunpack/releases).

## Notes

- **Sparse images**: If your super image is in Android sparse format, you need to
  convert it to a raw image first using `simg2img`:
  ```bash
  simg2img super.img super_raw.img
  lpunpack super_raw.img output/
  ```
- **Output files**: Partition images are written as `.img` files named after the
  partition (e.g., `system_a.img`, `vendor_a.img`).
- **Supported metadata**: V10.x (all minor versions). Slot 0 (`_a`) is used by default.

## License

Apache License 2.0
