# lpunpack

Extract partitions from Android super image — written in Go.

[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](LICENSE)

## Overview

`lpunpack` extracts partition images (`system.img`, `vendor.img`, `product.img`, etc.)
from Android super images. It is a pure Go reimplementation based on the official
[AOSP liblp format](https://android.googlesource.com/platform/system/core/+/refs/heads/main/liblp/).

## Installation

### From source

```bash
git clone https://github.com/soe1hom-arch/lpunpack.git
cd lpunpack
go build -o lpunpack .
```

### Download binary

Download from [GitHub Releases](https://github.com/soe1hom-arch/lpunpack/releases).

## Usage

```bash
lpunpack <super_image> [output_directory]
```

### Examples

```bash
# Extract to current directory
lpunpack super.img

# Extract to specific directory
lpunpack super.img output/

# Verbose mode
lpunpack -v super.img output/
```

## License

Apache License 2.0
