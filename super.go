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
	Offset      uint64
	NumElements uint64
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
	if g.StructSize > 52 {
		return nil, fmt.Errorf("struct_size too large: %d", g.StructSize)
	}
	if g.StructSize != 52 {
		return nil, fmt.Errorf("invalid struct size: %d", g.StructSize)
	}
		// Verify checksum
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

// Geometry magic in LE bytes
var geomMagicPattern = []byte{0x67, 0x44, 0x6c, 0x61}

func indexBytes(data, pattern []byte) int {
	if len(pattern) == 0 || len(data) < len(pattern) {
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

// Scan a region of the file for geometry magic, return valid geometry if found
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

		// Combine with overlap from previous chunk
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

			// Try to read and parse geometry at this offset
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

		// Save last 3 bytes for overlap with next chunk
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
		fmt.Fprintf(os.Stderr, "  Scanning entire file for geometry (may take a while)...\n")
	}
	chunkSize := int64(SCAN_CHUNK_SIZE)
	overlap := make([]byte, 0, 4)
	nextReport := int64(0)
	reportStep := sp.FileSize / 20 // 5% increments
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
							fmt.Fprintf(os.Stderr, "\n  Valid geometry at offset %d (%.2f MB)\n",
								absOff, float64(absOff)/1048576)
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
	return nil, 0, fmt.Errorf("no valid geometry found")
}

// ---- Main geometry entry point ----

func (sp *SuperImage) findGeometry() (*LpMetadataGeometry, int64, error) {
	tryOffsets := []int64{
		LP_PARTITION_RESERVED_BYTES,           // Standard primary: 4096
		LP_PARTITION_RESERVED_BYTES + LP_METADATA_GEOMETRY_SIZE, // Standard backup: 8192
		0, // Some images start at offset 0
		512, // After GPT header
		1024, // After GPT entries
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

	// Scan first 256MB + last 256MB
	if sp.Verbose {
		fmt.Fprintf(os.Stderr, "  Scanning first/last %d MB for geometry...\n",
			SCAN_LIMIT_BYTES/1024/1024)
	}

	// Scan first 256MB
	scanSize := int64(SCAN_LIMIT_BYTES)
	if sp.FileSize < scanSize*2 {
		scanSize = sp.FileSize / 2
	}
	g, off, err := sp.scanRegion(0, scanSize)
	if err == nil {
		return g, off, nil
	}

	// Scan last 256MB (different region)
	if sp.FileSize > scanSize {
		g, off, err = sp.scanRegion(sp.FileSize-scanSize, scanSize)
		if err == nil {
			return g, off, nil
		}
	}

	// Full file scan as last resort
	if sp.Verbose {
		fmt.Fprintf(os.Stderr, "  Limited scan failed, scanning entire file...\n")
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
	if len(buf) < 160 {
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
	off := 80
	h.Partitions = readDesc(buf, off)
	h.Extents = readDesc(buf, off+20)
	h.Groups = readDesc(buf, off+40)
	h.BlockDevices = readDesc(buf, off+60)
	if int(h.HeaderSize) >= off+80 {
		h.Flags = binary.LittleEndian.Uint32(buf[off+80 : off+84])
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
	if h.HeaderSize < 160 || h.HeaderSize > 164 {
		return nil, fmt.Errorf("invalid header size: %d", h.HeaderSize)
	}
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

func readDesc(buf []byte, off int) LpMetadataTableDescriptor {
	return LpMetadataTableDescriptor{
		Offset:      binary.LittleEndian.Uint64(buf[off : off+8]),
		NumElements: binary.LittleEndian.Uint64(buf[off+8 : off+16]),
		ElementSize: binary.LittleEndian.Uint32(buf[off+16 : off+20]),
	}
}

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
	for i := uint64(0); i < h.Extents.NumElements; i++ {
		eo := int64(h.Extents.Offset + i*uint64(h.Extents.ElementSize))
		if eo+24 > int64(len(td)) {
			return nil, fmt.Errorf("extent %d truncated", i)
		}
		extents[i].NumSectors = binary.LittleEndian.Uint64(td[eo : eo+8])
		extents[i].TargetType = binary.LittleEndian.Uint32(td[eo+8 : eo+12])
		extents[i].TargetData = binary.LittleEndian.Uint64(td[eo+12 : eo+20])
		extents[i].TargetSource = binary.LittleEndian.Uint32(td[eo+20 : eo+24])
		if extents[i].TargetType == LP_TARGET_TYPE_LINEAR &&
			extents[i].TargetSource >= uint32(h.BlockDevices.NumElements) {
			return nil, fmt.Errorf("extent %d: invalid block device %d", i, extents[i].TargetSource)
		}
	}

	// Parse partitions
	var parts []PartitionInfo
	for i := uint64(0); i < h.Partitions.NumElements; i++ {
		po := int64(h.Partitions.Offset + i*uint64(h.Partitions.ElementSize))
		if po+16 > int64(len(td)) {
			return nil, fmt.Errorf("partition %d truncated", i)
		}
		attrs := binary.LittleEndian.Uint32(td[po+4 : po+8])
		firstExt := int(binary.LittleEndian.Uint32(td[po+8 : po+12]))
		numExt := int(binary.LittleEndian.Uint32(td[po+12 : po+16]))

		elemSize := int64(h.Partitions.ElementSize)
		maxNameBytes := int(elemSize - 16)
		if maxNameBytes > 36 {
			maxNameBytes = 36
		}
		var name string
		if maxNameBytes > 0 && po+16+int64(maxNameBytes) <= int64(len(td)) {
			name = cString(td[po+16 : po+16+int64(maxNameBytes)])
		}
		if name == "" {
			continue
		}

		if firstExt+numExt < firstExt || firstExt+numExt > len(extents) {
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
	slot := uint32(0) // use _a

	// Try primary
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

	// Try backup
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
	g, geoOffset, err := sp.findGeometry()
	if err != nil {
		return err
	}
	if sp.Verbose {
		fmt.Fprintf(os.Stderr, "  Geometry offset: %d, maxSize=%d slots=%d blockSize=%d\n",
			geoOffset, g.MetadataMaxSize, g.MetadataSlotCount, g.LogicalBlockSize)
	}
	parts, err := sp.findMetadata(g, geoOffset)
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
