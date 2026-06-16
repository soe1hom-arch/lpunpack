// Copyright 2026 soe1hom-arch
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"os"
	"strings"
)

// AOSP liblp constants
const (
	LP_METADATA_GEOMETRY_MAGIC    = 0x616c4467
	LP_METADATA_HEADER_MAGIC      = 0x414C5030
	LP_METADATA_MAJOR_VERSION     = 10
	LP_METADATA_MINOR_VERSION_MIN = 0
	LP_METADATA_MINOR_VERSION_MAX = 2
	LP_METADATA_GEOMETRY_SIZE     = 4096
	LP_SECTOR_SIZE                = 512
	LP_PARTITION_RESERVED_BYTES   = 4096
	LP_TARGET_TYPE_LINEAR         = 0
	LP_TARGET_TYPE_ZERO           = 1
	LP_PARTITION_ATTR_SLOT_SUFFIXED = 1 << 1
)

// LpMetadataGeometry (52 bytes)
type LpMetadataGeometry struct {
	Magic             uint32
	StructSize        uint32
	Checksum          [32]byte
	MetadataMaxSize   uint32
	MetadataSlotCount uint32
	LogicalBlockSize  uint32
}

// LpMetadataTableDescriptor (20 bytes)
type LpMetadataTableDescriptor struct {
	Offset      uint64
	NumElements uint64
	ElementSize uint32
}

// LpMetadataHeader (V1_2 = 164 bytes, V1_0 = 160 bytes)
type LpMetadataHeader struct {
	Magic          uint32
	MajorVersion   uint16
	MinorVersion   uint16
	HeaderSize     uint32
	HeaderChecksum [32]byte
	TablesSize     uint32
	TablesChecksum [32]byte
	Partitions     LpMetadataTableDescriptor
	Extents        LpMetadataTableDescriptor
	Groups         LpMetadataTableDescriptor
	BlockDevices   LpMetadataTableDescriptor
	Flags          uint32
}

// LpMetadataExtent (24 bytes)
type LpMetadataExtent struct {
	NumSectors   uint64
	TargetType   uint32
	TargetData   uint64
	TargetSource uint32
}

// Parsed partition info for extraction
type PartitionInfo struct {
	Name    string
	Size    uint64
	Extents []LpMetadataExtent
}

type SuperImage struct {
	Filename   string
	FileSize   int64
	Partitions []PartitionInfo
	Verbose    bool
	file       *os.File
}

func OpenSuperImage(filename string, verbose bool) (*SuperImage, error) {
	f, err := os.Open(filename)
	if err != nil {
		return nil, fmt.Errorf("cannot open: %w", err)
	}
	fi, err := f.Stat()
	if err != nil {
		f.Close()
		return nil, fmt.Errorf("cannot stat: %w", err)
	}
	sp := &SuperImage{Filename: filename, FileSize: fi.Size(), file: f, Verbose: verbose}
	if err := sp.parse(); err != nil {
		f.Close()
		return nil, err
	}
	return sp, nil
}

func (sp *SuperImage) Close() error { return sp.file.Close() }

// ---- Geometry parsing ----

func parseGeometry(buf []byte) (*LpMetadataGeometry, error) {
	if len(buf) < 52 {
		return nil, fmt.Errorf("geometry buffer too small: %d", len(buf))
	}
	g := &LpMetadataGeometry{}
	g.Magic = binary.LittleEndian.Uint32(buf[0:4])
	g.StructSize = binary.LittleEndian.Uint32(buf[4:8])
	copy(g.Checksum[:], buf[8:40])
	g.MetadataMaxSize = binary.LittleEndian.Uint32(buf[40:44])
	g.MetadataSlotCount = binary.LittleEndian.Uint32(buf[44:48])
	g.LogicalBlockSize = binary.LittleEndian.Uint32(buf[48:52])

	if g.Magic != LP_METADATA_GEOMETRY_MAGIC {
		return nil, fmt.Errorf("invalid geometry magic signature")
	}
	if g.StructSize > 52 {
		return nil, fmt.Errorf("unrecognized geometry fields (struct_size=%d)", g.StructSize)
	}
	// Verify checksum
	tmp := make([]byte, g.StructSize)
	copy(tmp, buf[:g.StructSize])
	for i := 8; i < 40 && i < len(tmp); i++ {
		tmp[i] = 0
	}
	cs := sha256.Sum256(tmp)
	if cs != g.Checksum {
		return nil, fmt.Errorf("invalid geometry checksum")
	}
	if g.StructSize != 52 {
		return nil, fmt.Errorf("invalid geometry struct size: %d", g.StructSize)
	}
	if g.MetadataSlotCount == 0 {
		return nil, fmt.Errorf("invalid metadata slot count: 0")
	}
	if g.MetadataMaxSize%LP_SECTOR_SIZE != 0 {
		return nil, fmt.Errorf("metadata max size not sector-aligned: %d", g.MetadataMaxSize)
	}
	return g, nil
}

func readGeometryAt(f *os.File, offset int64) (*LpMetadataGeometry, error) {
	buf := make([]byte, LP_METADATA_GEOMETRY_SIZE)
	if _, err := f.ReadAt(buf, offset); err != nil {
		return nil, fmt.Errorf("read at %d: %w", offset, err)
	}
	return parseGeometry(buf)
}

func readGeometry(f *os.File, verbose bool) (*LpMetadataGeometry, error) {
	// Primary: offset 4096
	g, err := readGeometryAt(f, LP_PARTITION_RESERVED_BYTES)
	if err == nil {
		return g, nil
	}
	if verbose {
		fmt.Fprintf(os.Stderr, "  Primary geometry failed: %v\n", err)
	}
	// Backup: offset 8192
	g, err = readGeometryAt(f, LP_PARTITION_RESERVED_BYTES+LP_METADATA_GEOMETRY_SIZE)
	if err == nil {
		return g, nil
	}
	return nil, fmt.Errorf("no valid geometry found (primary and backup failed)")
}

// ---- Metadata offset calculations ----

func primaryMetadataOffset(g *LpMetadataGeometry, slot uint32) int64 {
	r := LP_PARTITION_RESERVED_BYTES + (LP_METADATA_GEOMETRY_SIZE * 2)
	return int64(r) + int64(g.MetadataMaxSize)*int64(slot)
}

func backupMetadataOffset(g *LpMetadataGeometry, slot uint32) int64 {
	start := int64(LP_PARTITION_RESERVED_BYTES + (LP_METADATA_GEOMETRY_SIZE * 2))
	start += int64(g.MetadataMaxSize) * int64(g.MetadataSlotCount)
	return start + int64(g.MetadataMaxSize)*int64(slot)
}

// ---- Metadata header parsing ----

func parseHeader(buf []byte) (*LpMetadataHeader, error) {
	if len(buf) < 160 {
		return nil, fmt.Errorf("header buffer too small: %d", len(buf))
	}
	h := &LpMetadataHeader{}
	h.Magic = binary.LittleEndian.Uint32(buf[0:4])
	h.MajorVersion = binary.LittleEndian.Uint16(buf[4:6])
	h.MinorVersion = binary.LittleEndian.Uint16(buf[6:8])
	h.HeaderSize = binary.LittleEndian.Uint32(buf[8:12])
	copy(h.HeaderChecksum[:], buf[12:44])
	h.TablesSize = binary.LittleEndian.Uint32(buf[44:48])
	copy(h.TablesChecksum[:], buf[48:80])

	off := 80
	readDesc := func(b []byte, o int) LpMetadataTableDescriptor {
		return LpMetadataTableDescriptor{
			Offset:      binary.LittleEndian.Uint64(b[o : o+8]),
			NumElements: binary.LittleEndian.Uint64(b[o+8 : o+16]),
			ElementSize: binary.LittleEndian.Uint32(b[o+16 : o+20]),
		}
	}
	h.Partitions = readDesc(buf, off)
	h.Extents = readDesc(buf, off+20)
	h.Groups = readDesc(buf, off+40)
	h.BlockDevices = readDesc(buf, off+60)

	if int(h.HeaderSize) >= off+80 {
		h.Flags = binary.LittleEndian.Uint32(buf[off+80 : off+84])
	}

	if h.Magic != LP_METADATA_HEADER_MAGIC {
		return nil, fmt.Errorf("invalid metadata header magic")
	}
	if h.MajorVersion != LP_METADATA_MAJOR_VERSION {
		return nil, fmt.Errorf("incompatible metadata version: %d.%d", h.MajorVersion, h.MinorVersion)
	}
	if h.MinorVersion > LP_METADATA_MINOR_VERSION_MAX {
		return nil, fmt.Errorf("metadata version too new: %d.%d", h.MajorVersion, h.MinorVersion)
	}
	if h.HeaderSize < 160 || h.HeaderSize > 164 {
		return nil, fmt.Errorf("invalid header size: %d", h.HeaderSize)
	}
	// Verify header checksum
	tmp := make([]byte, h.HeaderSize)
	copy(tmp, buf[:h.HeaderSize])
	for i := 12; i < 44 && i < len(tmp); i++ {
		tmp[i] = 0
	}
	cs := sha256.Sum256(tmp)
	if cs != h.HeaderChecksum {
		return nil, fmt.Errorf("invalid metadata header checksum")
	}
	return h, nil
}

// ---- Metadata table parsing ----

func readMetadataAt(f *os.File, g *LpMetadataGeometry, offset int64, verbose bool) ([]PartitionInfo, error) {
	buf := make([]byte, g.MetadataMaxSize)
	if _, err := f.ReadAt(buf, offset); err != nil {
		return nil, fmt.Errorf("read metadata at %d: %w", offset, err)
	}

	h, err := parseHeader(buf)
	if err != nil {
		return nil, err
	}

	// Table data starts after the header
	tblOff := int64(h.HeaderSize)
	if tblOff+int64(h.TablesSize) > int64(g.MetadataMaxSize) {
		return nil, fmt.Errorf("tables exceed metadata size")
	}
	td := buf[tblOff : tblOff+int64(h.TablesSize)]

	// Verify table checksum
	cs := sha256.Sum256(td)
	if cs != h.TablesChecksum {
		return nil, fmt.Errorf("invalid table checksum")
	}

	if verbose {
		fmt.Printf("  Metadata v%d.%d: %d partitions, %d extents\n",
			h.MajorVersion, h.MinorVersion,
			h.Partitions.NumElements, h.Extents.NumElements)
	}

	// Parse block devices (needed for validation)
	if h.BlockDevices.NumElements == 0 {
		return nil, fmt.Errorf("no block devices in metadata")
	}

	// Parse extents
	extents := make([]LpMetadataExtent, h.Extents.NumElements)
	for i := uint64(0); i < h.Extents.NumElements; i++ {
		eo := int64(h.Extents.Offset + i*uint64(h.Extents.ElementSize))
		var e LpMetadataExtent
		e.NumSectors = binary.LittleEndian.Uint64(td[eo : eo+8])
		e.TargetType = binary.LittleEndian.Uint32(td[eo+8 : eo+12])
		e.TargetData = binary.LittleEndian.Uint64(td[eo+12 : eo+20])
		e.TargetSource = binary.LittleEndian.Uint32(td[eo+20 : eo+24])
		if e.TargetType == LP_TARGET_TYPE_LINEAR &&
			e.TargetSource >= uint32(h.BlockDevices.NumElements) {
			return nil, fmt.Errorf("extent %d: invalid block device index %d", i, e.TargetSource)
		}
		extents[i] = e
	}

	// Parse partitions
	var parts []PartitionInfo
	for i := uint64(0); i < h.Partitions.NumElements; i++ {
		po := int64(h.Partitions.Offset + i*uint64(h.Partitions.ElementSize))
		if po+16 > int64(len(td)) {
			return nil, fmt.Errorf("partition %d: truncated entry", i)
		}
		nameSize := binary.LittleEndian.Uint32(td[po : po+4])
		attrs := binary.LittleEndian.Uint32(td[po+4 : po+8])
		firstExt := int(binary.LittleEndian.Uint32(td[po+8 : po+12]))
		numExt := int(binary.LittleEndian.Uint32(td[po+12 : po+16]))

		// Extract partition name
		var name string
		maxNameBytes := int(int64(h.Partitions.ElementSize) - 16)
		if maxNameBytes > 36 {
			maxNameBytes = 36
		}
		if maxNameBytes > 0 {
			nameBuf := td[po+16 : po+16+int64(maxNameBytes)]
			name = cString(nameBuf)
		}
		// Fallback: use nameSize
		if name == "" && nameSize > 0 && nameSize <= uint32(maxNameBytes) {
			nameBuf := td[po+16 : po+16+int64(nameSize)]
			name = cString(nameBuf)
		}
		if name == "" {
			continue
		}

		// Validate extent indices
		if firstExt+numExt < firstExt || firstExt+numExt > len(extents) {
			return nil, fmt.Errorf("partition %s: invalid extent list", name)
		}
		if numExt == 0 {
			continue
		}

		// Collect extents for this partition
		var pExts []LpMetadataExtent
		var pSize uint64
		for j := firstExt; j < firstExt+numExt; j++ {
			e := extents[j]
			if e.TargetType == LP_TARGET_TYPE_LINEAR {
				pExts = append(pExts, e)
				pSize += e.NumSectors * LP_SECTOR_SIZE
			}
		}

		// Apply slot suffix (_a for slot 0)
		if attrs&LP_PARTITION_ATTR_SLOT_SUFFIXED != 0 {
			name += "_a"
		}

		if pSize > 0 {
			parts = append(parts, PartitionInfo{
				Name:    name,
				Size:    pSize,
				Extents: pExts,
			})
		}
	}

	if len(parts) == 0 {
		return nil, fmt.Errorf("no valid partitions found in metadata")
	}
	return parts, nil
}

func readMetadata(f *os.File, g *LpMetadataGeometry, verbose bool) ([]PartitionInfo, error) {
	slot := uint32(0) // use slot 0 (_a)

	off := primaryMetadataOffset(g, slot)
	if verbose {
		fmt.Printf("  Primary metadata offset: %d (%.2f MB)\n", off, float64(off)/1048576)
	}
	parts, err := readMetadataAt(f, g, off, verbose)
	if err == nil {
		return parts, nil
	}
	if verbose {
		fmt.Fprintf(os.Stderr, "  Primary metadata failed: %v\n", err)
	}

	off = backupMetadataOffset(g, slot)
	if verbose {
		fmt.Printf("  Backup metadata offset: %d (%.2f MB)\n", off, float64(off)/1048576)
	}
	parts, err = readMetadataAt(f, g, off, verbose)
	if err == nil {
		return parts, nil
	}
	return nil, fmt.Errorf("no valid partition table found (primary and backup failed)")
}

// ---- Main parse entry point ----

func (sp *SuperImage) parse() error {
	g, err := readGeometry(sp.file, sp.Verbose)
	if err != nil {
		return err
	}
	if sp.Verbose {
		fmt.Printf("  Geometry: maxSize=%d slots=%d blockSize=%d\n",
			g.MetadataMaxSize, g.MetadataSlotCount, g.LogicalBlockSize)
	}
	parts, err := readMetadata(sp.file, g, sp.Verbose)
	if err != nil {
		return err
	}
	sp.Partitions = parts
	return nil
}

// ---- Utilities ----

func cString(buf []byte) string {
	n := len(buf)
	for i := 0; i < n; i++ {
		if buf[i] == 0 {
			return strings.TrimRight(string(buf[:i]), "\x00")
		}
	}
	return strings.TrimRight(string(buf), "\x00")
}

func formatSize(b int64) string {
	const unit = 1024
	if b < unit {
		return fmt.Sprintf("%d B", b)
	}
	div, exp := int64(unit), 0
	for n := b / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %cB", float64(b)/float64(div), "KMGTPE"[exp])
}
