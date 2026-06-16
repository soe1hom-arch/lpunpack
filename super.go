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

type LpMetadataGeometry struct {
	Magic             uint32
	StructSize        uint32
	Checksum          [32]byte
	MetadataMaxSize   uint32
	MetadataSlotCount uint32
	LogicalBlockSize  uint32
}

type LpMetadataTableDescriptor struct {
	Offset      uint32
	NumElements uint32
	ElementSize uint32
}

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

type LpMetadataExtent struct {
	NumSectors   uint64
	TargetType   uint32
	TargetData   uint64
	TargetSource uint32
}

// AOSP LpMetadataPartition: name FIRST (36 bytes), then attrs/extents
type LpMetadataPartition struct {
	Name             [36]byte // 0-35
	Attributes       uint32   // 36-39
	FirstExtentIndex uint32   // 40-43
	NumExtents       uint32   // 44-47
} // 48 bytes

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

// ---- Geometry ---- 

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
	}
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

// ---- Metadata parsing ----

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

	// Table descriptors: 12 bytes each, uint32 fields
	off := 80
	h.Partitions.Offset = binary.LittleEndian.Uint32(buf[off:]); off+=4
	h.Partitions.NumElements = binary.LittleEndian.Uint32(buf[off:]); off+=4
	h.Partitions.ElementSize = binary.LittleEndian.Uint32(buf[off:]); off+=4

	h.Extents.Offset = binary.LittleEndian.Uint32(buf[off:]); off+=4
	h.Extents.NumElements = binary.LittleEndian.Uint32(buf[off:]); off+=4
	h.Extents.ElementSize = binary.LittleEndian.Uint32(buf[off:]); off+=4

	h.Groups.Offset = binary.LittleEndian.Uint32(buf[off:]); off+=4
	h.Groups.NumElements = binary.LittleEndian.Uint32(buf[off:]); off+=4
	h.Groups.ElementSize = binary.LittleEndian.Uint32(buf[off:]); off+=4

	h.BlockDevices.Offset = binary.LittleEndian.Uint32(buf[off:]); off+=4
	h.BlockDevices.NumElements = binary.LittleEndian.Uint32(buf[off:]); off+=4
	h.BlockDevices.ElementSize = binary.LittleEndian.Uint32(buf[off:]); off+=4

	if int(h.HeaderSize) >= off+4 {
		h.Flags = binary.LittleEndian.Uint32(buf[off:off+4])
	}

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

// ---- Metadata tables parsing ----

func (sp *SuperImage) readMetadataAt(g *LpMetadataGeometry, offset int64) ([]PartitionInfo, error) {
	buf := make([]byte, g.MetadataMaxSize)
	if _, err := sp.file.ReadAt(buf, offset); err != nil {
		return nil, fmt.Errorf("read at %d: %w", offset, err)
	}

	h, err := parseHeader(buf)
	if err != nil {
		return nil, err
	}

	tblOff := int64(h.HeaderSize)
	if tblOff+int64(h.TablesSize) > int64(g.MetadataMaxSize) {
		return nil, fmt.Errorf("tables exceed metadata size")
	}
	td := buf[tblOff : tblOff+int64(h.TablesSize)]

	if sha256.Sum256(td) != h.TablesChecksum {
		return nil, fmt.Errorf("invalid table checksum")
	}

	if sp.Verbose {
		fmt.Fprintf(os.Stderr, "  Metadata v%d.%d: %d partitions, %d extents\n",
			h.MajorVersion, h.MinorVersion,
			h.Partitions.NumElements, h.Extents.NumElements)
	}

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
	// AOSP LpMetadataPartition layout:
	//   name[36] + attributes(4) + first_extent(4) + num_extents(4) = 48 bytes
	var parts []PartitionInfo
	for i := uint32(0); i < h.Partitions.NumElements; i++ {
		po := int64(h.Partitions.Offset) + int64(i)*int64(h.Partitions.ElementSize)
		_ = h.Partitions.ElementSize

		if po+48 > int64(len(td)) {
			return nil, fmt.Errorf("partition %d truncated", i)
		}

		// Read fixed struct (48 bytes)
		var part LpMetadataPartition
		copy(part.Name[:], td[po:po+36])
		part.Attributes = binary.LittleEndian.Uint32(td[po+36 : po+40])
		part.FirstExtentIndex = binary.LittleEndian.Uint32(td[po+40 : po+44])
		part.NumExtents = binary.LittleEndian.Uint32(td[po+44 : po+48])

		name := cString(part.Name[:])
		if name == "" {
			continue
		}

		if int(part.FirstExtentIndex+part.NumExtents) > len(extents) {
			return nil, fmt.Errorf("partition %s: invalid extent list (%d+%d > %d)",
				name, part.FirstExtentIndex, part.NumExtents, len(extents))
		}
		if part.NumExtents == 0 {
			continue
		}

		var pExts []LpMetadataExtent
		var pSize uint64
		for j := part.FirstExtentIndex; j < part.FirstExtentIndex+part.NumExtents; j++ {
			e := extents[j]
			if e.TargetType == LP_TARGET_TYPE_LINEAR {
				pExts = append(pExts, e)
				pSize += e.NumSectors * LP_SECTOR_SIZE
			}
		}

		if part.Attributes&LP_PARTITION_ATTR_SLOT_SUFFIXED != 0 {
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
	slot := uint32(0)

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
