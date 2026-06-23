# lpunpack

Extract partitions from Android super images — written in Go.

[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](LICENSE)
[![Go Version](https://img.shields.io/badge/Go-1.22+-00ADD8?logo=go)](https://go.dev)
[![build](https://github.com/soe1hom-arch/lpunpack/actions/workflows/build.yml/badge.svg)](https://github.com/soe1hom-arch/lpunpack/actions/workflows/build.yml)
[![Release](https://img.shields.io/github/v/release/soe1hom-arch/lpunpack?logo=github)](https://github.com/soe1hom-arch/lpunpack/releases)

## Overview

`lpunpack` extracts logical partition images (`system.img`, `vendor.img`, `product.img`, etc.)
from Android super images (`super.img`). It is a pure Go implementation based on the official
[AOSP liblp format](https://android.googlesource.com/platform/system/core/+/refs/heads/main/fs_mgr/liblp/).

Supports Android 10+ super partition format (LP metadata v10.x) and automatically handles
both standard and non-standard geometry layouts.

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

# Verbose mode with detailed metadata info
lpunpack -v super.img output/
```

### Options

| Flag | Description |
|------|-------------|
| `-v`, `--verbose` | Show geometry info, metadata version, and extraction progress |

### Example Output

```
$ lpunpack -v super_raw.img output/
  Geometry at offset 4096
  Geometry offset: 4096, maxSize=65536 slots=3 blockSize=4096
  Primary metadata offset: 12288 (0.01 MB)
  Metadata v10.2: 16 partitions, 8 extents
Super Image: super_raw.img (11.0 GB)
  Partitions: 8

Extracting odm_a (1.5 GB)...
Extracting product_a (3.3 GB)...
Extracting system_a (679.3 MB)...
Extracting system_dlkm_a (14.5 MB)...
Extracting system_ext_a (567.9 MB)...
Extracting vendor_a (1.6 GB)...
Extracting vendor_dlkm_a (45.1 MB)...
Extracting mi_ext_a (817.5 MB)...

Extracted 8 partition(s) to output/
```

## Installation

### From source (requires Go 1.22+)

```bash
git clone https://github.com/soe1hom-arch/lpunpack.git
cd lpunpack
go build -o lpunpack .
```

### Cross-compile for other platforms

```bash
# Linux ARM64 (Android Termux, Raspberry Pi)
GOOS=linux GOARCH=arm64 CGO_ENABLED=0 go build -o lpunpack .

# Linux AMD64 (PC/server)
GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -o lpunpack .

# macOS Intel
GOOS=darwin GOARCH=amd64 CGO_ENABLED=0 go build -o lpunpack .

# macOS Apple Silicon (M1/M2/M3)
GOOS=darwin GOARCH=arm64 CGO_ENABLED=0 go build -o lpunpack .

# Windows
GOOS=windows GOARCH=amd64 CGO_ENABLED=0 go build -o lpunpack.exe .
```

### Pre-built binaries

Download from the [Releases page](https://github.com/soe1hom-arch/lpunpack/releases).

Pre-built for: `linux/amd64`, `linux/arm64`, `darwin/amd64`, `darwin/arm64`, `windows/amd64`.

## How It Works

The tool follows the AOSP liblp on-disk format:

1. **Geometry** — reads `LpMetadataGeometry` from offset 4096 (standard) or falls back to
   scanning for the correct magic value if not at the expected location
2. **Metadata** — locates the partition table using geometry fields (`metadata_max_size`,
   `metadata_slot_count`) and validates with SHA256 checksums
3. **Extents** — reads extent table entries that map partition data to physical sectors
4. **Extraction** — copies data from the super image using extent information

### Supported Metadata Versions

| Version | Description |
|---------|-------------|
| V10.0 | Initial LP metadata format (Android 10) |
| V10.1 | Added `updated` attribute (Android 11) |
| V10.2 | Extended header with flags field (Android 12+) |

## Notes

- **Sparse images**: If your super image is in Android sparse format, you need to
  convert it to a raw image first using `simg2img`:
  ```bash
  simg2img super.img super_raw.img
  lpunpack super_raw.img output/
  ```
- **Output files**: Partition images are written as `.img` files named after the
  partition (e.g., `system_a.img`, `vendor_a.img`).
- **Slot 0** (`_a` suffix) is used by default.

## Troubleshooting

| Error | Cause & Solution |
|-------|------------------|
| `no valid geometry found` | File is not a super image or is in sparse format. Convert with `simg2img` first. |
| `tables exceed metadata size` | Corrupted or unsupported metadata format. |
| `invalid block device` | Extent references a non-existent block device. Unusual — file may be corrupted. |
| `permission denied` when extracting | Make sure output directory is writable. |

## Credits

- **soe1hom-arch** — Go implementation and maintenance
- This project is a Go port of the `lpunpack` utility from the
  [Android Open Source Project (AOSP)](https://android.googlesource.com/platform/system/core/+/refs/heads/main/fs_mgr/liblp/).
- [AOSP liblp](https://android.googlesource.com/platform/system/core/+/refs/heads/main/fs_mgr/liblp/) — Logical partition metadata format specification

## License

Apache License 2.0
