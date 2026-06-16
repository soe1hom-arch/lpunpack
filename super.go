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
	SCAN_CHUNK_SIZE               = 4 * 1024 * 1024
	SCAN_LIMIT_BYTES              = 256 * 1024 * 1024
)

// ---- AOSP liblp structs ----

// LpMetadataGeometry (52 bytes)
type LpMetadataGeometry struct {
	Magic             uint32
	StructSize        uint32
	Checksum          [32]byte
	MetadataMaxSize   uint32
	MetadataSlotCount uint32
	LogicalBlockSize  uint32
}

// LpMetadataTableDescriptor (12 bytes in AOSP: all uint32!)
type LpMetadataTableDescriptor struct {
	Offset      uint32 // offset from end of header
	NumElements uint32 // number of entries
	ElementSize uint32 // size of each entry
}

// LpMetadataHeader (V1_0 = 128 bytes, V1_2 = 132 bytes, actual file may have more)
type LpMetadataHeader struct {
	Magic          uint32   // 0
	MajorVersion   uint16   // 4
	MinorVersion   uint16   // 6
	HeaderSize     uint32   // 8
	HeaderChecksum [32]byte // 12
	TablesSize     uint32   // 44
	TablesChecksum [32]byte // 48
	// V1_0/V1_2 fields end at 80, then table descriptors (12 bytes each)
	Partitions   LpMetadataTableDescriptor // 80
	Extents      LpMetadataTableDescriptor // 92
	Groups       LpMetadataTableDescriptor // 104
	BlockDevices LpMetadataTableDescriptor // 116
	// V1_2+: flags at 128
	// File may have more bytes (header_size=256)
	Flags uint32 // 128
}

// LpMetadataExtent (24 bytes)
type LpMetadataExtent struct {
	NumSectors   uint64 // 0
	TargetType   uint32 // 8
	TargetData   uint64 // 12
	TargetSource uint32 // 20
}

// LpMetadataPartition (16 + name_size bytes, but usually 52 with 36-byte name)
type LpMetadataPartition struct {
	NameSize         uint32   // 0
	Attributes       uint32   // 4
	FirstExtentIndex uint32   // 8
	NumExtents       uint32   // 12
	// Name at offset 16, variable length
}

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
		return nil, fmt.Errorf("buffer too small: %d", len(buf))
	}
	g := &LpMetadataGeometry{}
	g.Magic = binary.LittleEndian.Uint32(buf[0:4])
	g.StructSize = binary.LittleEndian.Uint32(buf[4:8])
	copy(g.Checksum[:], buf[8:40])
	g.MetadataMaxSize = binary.LittleEndian.Uint32(buf[40:44])
	g.MetadataSlotCount = binary.LittleEndian.Uint32(buf[44:48])
	g.LogicalBlockSize = binary.LittleEndian.Uint32(buf[48:52])

	if g.Magic != LP_METADATA_GEOMETRY_MAGIC {
		return nil, fmt.Errorf("invalid magic")
	}
	if g.StructSize != 52 {
		return nil, fmt.Errorf("invalid struct size: %d", g.StructSize)
	}
	tmp := make([]byte, 52)
	copy(tmp, buf[:52])
	for i := 8; i < 40; i++ {
		tmp[i] = 0
	}
	if sha256.Sum256(tmp) != g.Checksum {
		return nil, fmt.Errorf("invalid checksum")
	}
	if g.MetadataSlotCount == 0 {
		return nil, fmt.Errorf("slot count is 0")
	}
	if g.MetadataMaxSize == 0 || g.MetadataMaxSize%LP_SECTOR_SIZE != 0 {
		return nil, fmt.Errorf("invalid max_size: %d", g.MetadataMaxSize)
	}
	return g, nil
}

func readGeometryAt(f *os.File, offset int64) (*LpMetadataGeometry, error) {
	buf := make([]byte, 52)
	if _, err := f.ReadAt(buf, offset); err != nil {
		return nil, err
	}
	return parseGeometry(buf)
}

// ---- Geometry scanning ----

var geomMagicPattern = []byte{0x67, 0x44, 0x6c, 0x61}

func indexBytes(data, pattern []byte) int {
	if len(data) < len(pattern) {
		return -1
	}
	for i := 0; i <= len(data)-len(pattern); i++ {
		match := true
		for j := 0; j < len(pattern); j++ {
			if data[i+j] != pattern[j] {
				match = false
				break
			}
		}
		if match {
			return i
		}
	}
	return -1
}

func (sp *SuperImage) scanRegion(start, length int64) (*LpMetadataGeometry, int64, error) {
	end := start + length
	if end > sp.FileSize {
		end = sp.FileSize
	}
	pos := start
	overlap := make([]byte, 0, 4)
	for pos < end {
		chunkSize := int64(SCAN_CHUNK_SIZE)
		if pos+chunkSize > end {
			chunkSize = end - pos
		}
		if chunkSize < 4 {
			break
		}
		buf := make([]byte, chunkSize)
		n, err := sp.file.ReadAt(buf, pos)
		if err != nil || n < 4 {
			break
		}
		data := buf[:n]
		searchData := data
		if len(overlap) > 0 {
			searchData = append(overlap, data...)
		}
		idx := 0
		for {
			hit := indexBytes(searchData[idx:], geomMagicPattern)
			if hit < 0 {
				break
			}
			relOff := idx + hit
			absOff := pos + int64(relOff)
			if len(overlap) > 0 {
				absOff = pos - int64(len(overlap)) + int64(relOff)
			}
			if absOff+52 <= sp.FileSize {
				geoBuf := make([]byte, 52)
				if _, e := sp.file.ReadAt(geoBuf, absOff); e == nil {
					if g, e := parseGeometry(geoBuf); e == nil {
						return g, absOff, nil
					}
				}
			}
			idx += hit + 1
		}
		if n >= 3 {
			overlap = append(overlap[:0], buf[n-3:n]...)
		} else {
			overlap = overlap[:0]
		}
		pos += int64(n)
	}
	return nil, 0, fmt.Errorf("no geometry found in region")
}

func (sp *SuperImage) scanFile() (*LpMetadataGeometry, int64, error) {
	if sp.Verbose {
		fmt.Fprintf(os.Stderr, "  Scanning entire file for geometry...\n")
	}
	chunkSize := int64(SCAN_CHUNK_SIZE)
	overlap := make([]byte, 0, 4)
	nextReport := int64(0)
	reportStep := sp.FileSize / 20
	if reportStep < chunkSize {
		reportStep = chunkSize
	}
	for pos := int64(0); pos < sp.FileSize; pos += chunkSize {
		readSize := chunkSize
		if pos+readSize > sp.FileSize {
			readSize = sp.FileSize - pos
		}
		buf := make([]byte, readSize)
		n, err := sp.file.ReadAt(buf, pos)
		if err != nil || n < 4 {
			break
		}
		data := buf[:n]
		searchData := data
		if len(overlap) > 0 {
			searchData = make([]byte, len(overlap)+n)
			copy(searchData, overlap)
			copy(searchData[len(overlap):], data)
		}
		idx := 0
		for {
			hit := indexBytes(searchData[idx:], geomMagicPattern)
			if hit < 0 {
				break
			}
			relOff := idx + hit
			absOff := pos + int64(relOff)
			if len(overlap) > 0 {
				absOff = pos - int64(len(overlap)) + int64(relOff)
			}
			if absOff+52 <= sp.FileSize {
				geoBuf := make([]byte, 52)
				if _, e := sp.file.ReadAt(geoBuf, absOff); e == nil {
					if g, e := parseGeometry(geoBuf); e == nil {
						if sp.Verbose {
							fmt.Fprintf(os.Stderr, "\n  Geometry at offset %d\n", absOff)
						}
						return g, absOff, nil
					}
				}
			}
			idx += hit + 1
		}
		if n >= 3 {
			overlap = append(overlap[:0], buf[n-3:n]...)
		} else {
			overlap = overlap[:0]
		}
		if sp.Verbose && pos >= nextReport {
			pct := pos * 100 / sp.FileSize
			fmt.Fprintf(os.Stderr, "\r  Scanning... %d%%", pct)
			nextReport += reportStep
		}
	}
	if sp.Verbose {
		fmt.Fprintf(os.Stderr, "\r  Scanning... 100%%\n")
	}
	return nil, 0, fmt.Errorf("no geometry found")
}

func (sp *SuperImage) findGeometry() (*LpMetadataGeometry, int64, error) {
	// Method 1-2: Standard AOSP offsets
	tryOffsets := []int64{
		LP_PARTITION_RESERVED_BYTES,
		LP_PARTITION_RESERVED_BYTES + LP_METADATA_GEOMETRY_SIZE,
		0, 512, 1024,
	}
	for _, off := range tryOffsets {
		if off+52 > sp.FileSize {
			continue
		}
		g, err := readGeometryAt(sp.file, off)
		if err == nil {
			if sp.Verbose {
				fmt.Fprintf(os.Stderr, "  Geometry at offset %d\n", off)
			}
			return g, off, nil
		}
		if sp.Verbose {
			fmt.Fprintf(os.Stderr, "  Offset %d: %v\n", off, err)
		}
	}
	// Method 3: Scan first/last 256MB
	if sp.Verbose {
		fmt.Fprintf(os.Stderr, "  Scanning first/last %d MB...\n", SCAN_LIMIT_BYTES/1024/1024)
	}
	scanSize := int64(SCAN_LIMIT_BYTES)
	if sp.FileSize < scanSize*2 {
		scanSize = sp.FileSize / 2
	}
	g, off, err := sp.scanRegion(0, scanSize)
	if err == nil {
		return g, off, nil
	}
	if sp.FileSize > scanSize {
		g, off, err = sp.scanRegion(sp.FileSize-scanSize, scanSize)
		if err == nil {
			return g, off, nil
		}
	}
	// Method 4: Full scan
	return sp.scanFile()
}

// ---- Metadata offset calculations ----

func primaryMetadataOffset(g *LpMetadataGeometry, geoOffset int64, slot uint32) int64 {
	if geoOffset < LP_PARTITION_RESERVED_BYTES {
		return geoOffset + LP_METADATA_GEOMETRY_SIZE + int64(g.MetadataMaxSize)*int64(slot)
	}
	r := LP_PARTITION_RESERVED_BYTES + (LP_METADATA_GEOMETRY_SIZE * 2)
	return int64(r) + int64(g.MetadataMaxSize)*int64(slot)
}

func backupMetadataOffset(g *LpMetadataGeometry, geoOffset int64, slot uint32) int64 {
	if geoOffset < LP_PARTITION_RESERVED_BYTES {
		start := geoOffset + LP_METADATA_GEOMETRY_SIZE
		start += int64(g.MetadataMaxSize) * int64(g.MetadataSlotCount)
		return start + int64(g.MetadataMaxSize)*int64(slot)
	}
	start := int64(LP_PARTITION_RESERVED_BYTES + (LP_METADATA_GEOMETRY_SIZE * 2))
	start += int64(g.MetadataMaxSize) * int64(g.MetadataSlotCount)
	return start + int64(g.MetadataMaxSize)*int64(slot)
}

// ---- Metadata header parsing ----

func parseHeader(buf []byte) (*LpMetadataHeader, error) {
	if len(buf) < 128 {
		return nil, fmt.Errorf("buffer too small: %d", len(buf))
	}
	h := &LpMetadataHeader{}
	h.Magic = binary.LittleEndian.Uint32(buf[0:4])
	h.MajorVersion = binary.LittleEndian.Uint16(buf[4:6])
	h.MinorVersion = binary.LittleEndian.Uint16(buf[6:8])
	h.HeaderSize = binary.LittleEndian.Uint32(buf[8:12])
	copy(h.HeaderChecksum[:], buf[12:44])
	h.TablesSize = binary.LittleEndian.Uint32(buf[44:48])
	copy(h.TablesChecksum[:], buf[48:80])

	// Table descriptors (12 bytes each, all uint32)
	h.Partitions.Offset = binary.LittleEndian.Uint32(buf[80:84])
	h.Partitions.NumElements = binary.LittleEndian.Uint32(buf[84:88])
	h.Partitions.ElementSize = binary.LittleEndian.Uint32(buf[88:92])

	h.Extents.Offset = binary.LittleEndian.Uint32(buf[92:96])
	h.Extents.NumElements = binary.LittleEndian.Uint32(buf[96:100])
	h.Extents.ElementSize = binary.LittleEndian.Uint32(buf[100:104])

	h.Groups.Offset = binary.LittleEndian.Uint32(buf[104:108])
	h.Groups.NumElements = binary.LittleEndian.Uint32(buf[108:112])
	h.Groups.ElementSize = binary.LittleEndian.Uint32(buf[112:116])

	h.BlockDevices.Offset = binary.LittleEndian.Uint32(buf[116:120])
	h.BlockDevices.NumElements = binary.LittleEndian.Uint32(buf[120:124])
	h.BlockDevices.ElementSize = binary.LittleEndian.Uint32(buf[124:128])

	// Flags at byte 128 (V1.2+)
	if int(h.HeaderSize) >= 132 {
		h.Flags = binary.LittleEndian.Uint32(buf[128:132])
	}

	// Validate
	if h.Magic != LP_METADATA_HEADER_MAGIC {
		return nil, fmt.Errorf("invalid header magic")
	}
	if h.MajorVersion != LP_METADATA_MAJOR_VERSION {
		return nil, fmt.Errorf("version %d.%d", h.MajorVersion, h.MinorVersion)
	}
	if h.MinorVersion > LP_METADATA_MINOR_VERSION_MAX {
		return nil, fmt.Errorf("version too new %d.%d", h.MajorVersion, h.MinorVersion)
	}
	if h.HeaderSize < 128 {
		return nil, fmt.Errorf("invalid header size: %d", h.HeaderSize)
	}
	// Validate header checksum
	tmp := make([]byte, h.HeaderSize)
	copy(tmp, buf[:h.HeaderSize])
	for i := 12; i < 44 && i < len(tmp); i++ {
		tmp[i] = 0
	}
	if sha256.Sum256(tmp) != h.HeaderChecksum {
		return nil, fmt.Errorf("invalid header checksum")
	}
	return h, nil
}

// ---- Metadata reading ----

func (sp *SuperImage) readMetadataAt(g *LpMetadataGeometry, offset int64) ([]PartitionInfo, error) {
	buf := make([]byte, g.MetadataMaxSize)
	if _, err := sp.file.ReadAt(buf, offset); err != nil {
		return nil, fmt.Errorf("read at %d: %w", offset, err)
	}

	h, err := parseHeader(buf)
	if err != nil {
		return nil, err
	}

	// Check tables don't exceed metadata size
	tblOff := int64(h.HeaderSize)
	if tblOff+int64(h.TablesSize) > int64(g.MetadataMaxSize) {
		return nil, fmt.Errorf("tables exceed metadata size")
	}
	td := buf[tblOff : tblOff+int64(h.TablesSize)]

	// Validate tables checksum
	if sha256.Sum256(td) != h.TablesChecksum {
		return nil, fmt.Errorf("invalid table checksum")
	}

	if sp.Verbose {
		fmt.Fprintf(os.Stderr, "  Metadata v%d.%d: %d partitions, %d extents\n",
			h.MajorVersion, h.MinorVersion,
			h.Partitions.NumElements, h.Extents.NumElements)
	}

	// Parse block devices (needed for validation)
	if h.BlockDevices.NumElements == 0 {
		return nil, fmt.Errorf("no block devices")
	}

	// Parse extents
	extents := make([]LpMetadataExtent, h.Extents.NumElements)
	for i := uint32(0); i < h.Extents.NumElements; i++ {
		eo := int64(h.Extents.Offset) + int64(i)*int64(h.Extents.ElementSize)
		if eo+24 > int64(len(td)) {
			return nil, fmt.Errorf("extent %d truncated", i)
		}
		extents[i].NumSectors = binary.LittleEndian.Uint64(td[eo : eo+8])
		extents[i].TargetType = binary.LittleEndian.Uint32(td[eo+8 : eo+12])
		extents[i].TargetData = binary.LittleEndian.Uint64(td[eo+12 : eo+20])
		extents[i].TargetSource = binary.LittleEndian.Uint32(td[eo+20 : eo+24])
		if extents[i].TargetType == LP_TARGET_TYPE_LINEAR &&
			extents[i].TargetSource >= h.BlockDevices.NumElements {
			return nil, fmt.Errorf("extent %d: invalid block device", i)
		}
	}

	// Parse partitions
	var parts []PartitionInfo
	for i := uint32(0); i < h.Partitions.NumElements; i++ {
		po := int64(h.Partitions.Offset) + int64(i)*int64(h.Partitions.ElementSize)
		if po+16 > int64(len(td)) {
			return nil, fmt.Errorf("partition %d truncated", i)
		}
		nameSize := binary.LittleEndian.Uint32(td[po : po+4])
		attrs := binary.LittleEndian.Uint32(td[po+4 : po+8])
		firstExt := binary.LittleEndian.Uint32(td[po+8 : po+12])
		numExt := binary.LittleEndian.Uint32(td[po+12 : po+16])

		// Extract name from bytes after fixed fields
		elemSize := int64(h.Partitions.ElementSize)
		var name string
		if elemSize > 16 && po+elemSize <= int64(len(td)) {
			name = cString(td[po+16 : po+elemSize])
		}
		if name == "" && nameSize > 0 {
			maxNameLen := int64(nameSize)
			if maxNameLen > elemSize-16 {
				maxNameLen = elemSize - 16
			}
			if maxNameLen > 0 && po+16+maxNameLen <= int64(len(td)) {
				name = cString(td[po+16 : po+16+maxNameLen])
			}
		}
		if name == "" {
			continue
		}

		if int(firstExt)+int(numExt) > len(extents) {
			return nil, fmt.Errorf("partition %s: invalid extent list", name)
		}
		if numExt == 0 {
			continue
		}

		var pExts []LpMetadataExtent
		var pSize uint64
		for j := firstExt; j < firstExt+numExt; j++ {
			e := extents[j]
			if e.TargetType == LP_TARGET_TYPE_LINEAR {
				pExts = append(pExts, e)
				pSize += e.NumSectors * LP_SECTOR_SIZE
			}
		}

		if attrs&LP_PARTITION_ATTR_SLOT_SUFFIXED != 0 {
			name += "_a"
		}

		if pSize > 0 {
			parts = append(parts, PartitionInfo{Name: name, Size: pSize, Extents: pExts})
		}
	}

	if len(parts) == 0 {
		return nil, fmt.Errorf("no valid partitions found")
	}
	return parts, nil
}

func (sp *SuperImage) findMetadata(g *LpMetadataGeometry, geoOffset int64) ([]PartitionInfo, error) {
	slot := uint32(0) // _a

	off := primaryMetadataOffset(g, geoOffset, slot)
	if sp.Verbose {
		fmt.Fprintf(os.Stderr, "  Primary metadata offset: %d (%.2f MB)\n", off, float64(off)/1048576)
	}
	parts, err := sp.readMetadataAt(g, off)
	if err == nil {
		return parts, nil
	}
	if sp.Verbose {
		fmt.Fprintf(os.Stderr, "  Primary metadata failed: %v\n", err)
	}

	off = backupMetadataOffset(g, geoOffset, slot)
	if sp.Verbose {
		fmt.Fprintf(os.Stderr, "  Backup metadata offset: %d (%.2f MB)\n", off, float64(off)/1048576)
	}
	parts, err = sp.readMetadataAt(g, off)
	if err == nil {
		return parts, nil
	}
	return nil, fmt.Errorf("no valid partition table found (primary and backup failed)")
}

// ---- Main parse ----

func (sp *SuperImage) parse() error {
	g, geoOff, err := sp.findGeometry()
	if err != nil {
		return err
	}
	if sp.Verbose {
		fmt.Fprintf(os.Stderr, "  Geometry offset: %d, maxSize=%d slots=%d blockSize=%d\n",
			geoOff, g.MetadataMaxSize, g.MetadataSlotCount, g.LogicalBlockSize)
	}
	parts, err := sp.findMetadata(g, geoOff)
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
