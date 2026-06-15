// Copyright 2026 soe1hom-arch
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"io"
	"os"
)

// Constants from AOSP liblp metadata_format.h
const (
	LpMetadataGeometryMagic = 0x504D504C // "LPMP"
	LpMetadataHeaderMagic  = 0x484D504C // "LPMH"

	LpMetadataGeometrySize = 52
	LpMetadataHeaderSize   = 24

	LpMetadataExtentTypeLinear = 0

	DefaultBlockSize = 4096
	SectorSize       = 512
)

// LpMetadataGeometry from AOSP liblp (packed, 52 bytes)
type LpMetadataGeometry struct {
	Magic             [4]byte // "LPMP"
	StructSize        uint32
	Checksum          [32]byte
	MetadataMaxSize   uint32
	MetadataSlotCount uint32
	LogicalBlockSize  uint32
}

// LpMetadataHeader from AOSP liblp (packed, 24 bytes)
type LpMetadataHeader struct {
	Magic         [4]byte // "LPMH"
	MajorVersion  uint32 // 10
	MinorVersion  uint32 // 0
	HeaderSize    uint32
	NumPartitions uint32
	NumExtents    uint32
}

// LpMetadataPartition entry
type LpMetadataPartition struct {
	NameSize         uint32
	Attributes       uint32
	FirstExtentIndex uint32
	NumExtents       uint32
	Name             string
}

// LpMetadataExtent entry (32 bytes)
type LpMetadataExtent struct {
	NumSectors      uint64
	Sector          uint64
	PartitionSector uint64
	Type            uint64
}

// PartitionInfo holds extracted partition info
type PartitionInfo struct {
	Name    string
	Size    uint64
	Extents []LpMetadataExtent
}

// SuperImage represents a parsed Android super image
type SuperImage struct {
	Filename   string
	FileSize   int64
	Geometry   LpMetadataGeometry
	Partitions []PartitionInfo
	file       *os.File
}

// OpenSuperImage opens and parses a super image
func OpenSuperImage(filename string) (*SuperImage, error) {
	file, err := os.Open(filename)
	if err != nil {
		return nil, fmt.Errorf("cannot open file: %w", err)
	}

	fi, err := file.Stat()
	if err != nil {
		file.Close()
		return nil, fmt.Errorf("cannot stat file: %w", err)
	}

	sp := &SuperImage{
		Filename: filename,
		FileSize: fi.Size(),
		file:     file,
	}

	if err := sp.parseMetadata(); err != nil {
		file.Close()
		return nil, err
	}

	return sp, nil
}

func (sp *SuperImage) parseMetadata() error {
	geometry, err := sp.findGeometry()
	if err != nil {
		return fmt.Errorf("cannot find geometry: %w", err)
	}
	sp.Geometry = *geometry

	blockSize := int64(sp.Geometry.LogicalBlockSize)
	if blockSize == 0 {
		blockSize = DefaultBlockSize
	}

	metadataMaxSize := int64(sp.Geometry.MetadataMaxSize)
	if metadataMaxSize == 0 {
		return fmt.Errorf("invalid metadata_max_size: 0")
	}

	// Geometry is stored at the last logical block
	geometryOffset := alignDown(sp.FileSize, blockSize) - blockSize

	// Metadata slot 0 is right before the geometry
	slot0Offset := geometryOffset - metadataMaxSize
	if slot0Offset < 0 {
		return fmt.Errorf("metadata slot offset is negative (file too small)")
	}

	// Parse the metadata slot 0 (primary)
	if err := sp.readMetadataSlot(slot0Offset); err != nil {
		return fmt.Errorf("cannot read metadata slot: %w", err)
	}

	return nil
}

func (sp *SuperImage) findGeometry() (*LpMetadataGeometry, error) {
	blockSize := int64(DefaultBlockSize)
	candidates := []int64{
		alignDown(sp.FileSize, blockSize) - blockSize,
		sp.FileSize - int64(LpMetadataGeometrySize),
		sp.FileSize - int64(4096),
		sp.FileSize - int64(SectorSize)*2,
		sp.FileSize - int64(SectorSize),
	}

	seen := make(map[int64]bool)
	for _, offset := range candidates {
		if offset < 0 || seen[offset] {
			continue
		}
		seen[offset] = true

		buf := make([]byte, LpMetadataGeometrySize)
		n, err := sp.file.ReadAt(buf, offset)
		if err != nil || n < LpMetadataGeometrySize {
			continue
		}

		var geo LpMetadataGeometry
		copy(geo.Magic[:], buf[0:4])
		if string(geo.Magic[:]) != "LPMP" {
			continue
		}

		geo.StructSize = binary.LittleEndian.Uint32(buf[4:8])
		copy(geo.Checksum[:], buf[8:40])
		geo.MetadataMaxSize = binary.LittleEndian.Uint32(buf[40:44])
		geo.MetadataSlotCount = binary.LittleEndian.Uint32(buf[44:48])
		geo.LogicalBlockSize = binary.LittleEndian.Uint32(buf[48:52])

		if geo.StructSize < 12 || geo.MetadataMaxSize == 0 {
			continue
		}
		if geo.LogicalBlockSize == 0 {
			geo.LogicalBlockSize = DefaultBlockSize
		}

		// Verify SHA256 checksum
		if !geo.verifyChecksum(buf) {
			continue
		}

		return &geo, nil
	}

	return nil, fmt.Errorf("no valid LPMP geometry found in super image")
}

func (geo *LpMetadataGeometry) verifyChecksum(buf []byte) bool {
	if geo.StructSize < 12 {
		return false
	}
	// SHA256 of everything after the checksum field (offset 40 onwards)
	hasher := sha256.New()
	hasher.Write(buf[40:geo.StructSize])
	sum := hasher.Sum(nil)
	for i := 0; i < 32; i++ {
		if sum[i] != geo.Checksum[i] {
			return false
		}
	}
	return true
}

func (sp *SuperImage) readMetadataSlot(offset int64) error {
	buf := make([]byte, sp.Geometry.MetadataMaxSize)
	n, err := sp.file.ReadAt(buf, offset)
	if err != nil && err != io.EOF {
		return fmt.Errorf("cannot read metadata slot at %d: %w", offset, err)
	}
	if n < LpMetadataHeaderSize {
		return fmt.Errorf("metadata slot too small: %d bytes", n)
	}

	// Parse header
	var header LpMetadataHeader
	copy(header.Magic[:], buf[0:4])
	header.MajorVersion = binary.LittleEndian.Uint32(buf[4:8])
	header.MinorVersion = binary.LittleEndian.Uint32(buf[8:12])
	header.HeaderSize = binary.LittleEndian.Uint32(buf[12:16])
	header.NumPartitions = binary.LittleEndian.Uint32(buf[16:20])
	header.NumExtents = binary.LittleEndian.Uint32(buf[20:24])

	if string(header.Magic[:]) != "LPMH" {
		return fmt.Errorf("invalid metadata header magic")
	}
	if header.MajorVersion != 10 {
		return fmt.Errorf("unsupported metadata version: %d.%d", header.MajorVersion, header.MinorVersion)
	}

	// Calculate the start of partition entries
	headerSize := int64(header.HeaderSize)
	if headerSize < int64(LpMetadataHeaderSize) {
		headerSize = int64(LpMetadataHeaderSize)
	}

	// Read all extents first (they come after all partition entries)
	// First pass: skip over partition entries to find extents
	extentOffset := headerSize
	for i := uint32(0); i < header.NumPartitions; i++ {
		if int(extentOffset+16) > n {
			break
		}
		nameSize := binary.LittleEndian.Uint32(buf[extentOffset : extentOffset+4])
		entrySize := int64(16 + nameSize)
		extentOffset += entrySize
	}

	// Read extents
	extents := make([]LpMetadataExtent, header.NumExtents)
	for i := uint32(0); i < header.NumExtents; i++ {
		eStart := extentOffset + int64(i)*32
		if int(eStart+32) > n {
			return fmt.Errorf("extent %d exceeds metadata slot", i)
		}
		extents[i] = LpMetadataExtent{
			NumSectors:      binary.LittleEndian.Uint64(buf[eStart : eStart+8]),
			Sector:          binary.LittleEndian.Uint64(buf[eStart+8 : eStart+16]),
			PartitionSector: binary.LittleEndian.Uint64(buf[eStart+16 : eStart+24]),
			Type:            binary.LittleEndian.Uint64(buf[eStart+24 : eStart+32]),
		}
	}

	// Read partitions
	partOffset := headerSize
	for i := uint32(0); i < header.NumPartitions; i++ {
		if int(partOffset+16) > n {
			break
		}

		nameSize := binary.LittleEndian.Uint32(buf[partOffset : partOffset+4])
		attributes := binary.LittleEndian.Uint32(buf[partOffset+4 : partOffset+8])
		firstExtIdx := binary.LittleEndian.Uint32(buf[partOffset+8 : partOffset+12])
		numExts := binary.LittleEndian.Uint32(buf[partOffset+12 : partOffset+16])

		var name string
		if nameSize > 0 {
			nameEnd := partOffset + 16 + int64(nameSize)
			if int(nameEnd) <= n {
				nameBytes := buf[partOffset+16 : nameEnd]
				// Trim null terminator
				for j := 0; j < len(nameBytes); j++ {
					if nameBytes[j] == 0 {
						nameBytes = nameBytes[:j]
						break
					}
				}
				name = string(nameBytes)
			}
		}

		_ = attributes

		// Collect extents for this partition
		var partExtents []LpMetadataExtent
		var partSize uint64
		for j := firstExtIdx; j < firstExtIdx+numExts && j < uint32(len(extents)); j++ {
			partExtents = append(partExtents, extents[j])
			partSize += extents[j].NumSectors * SectorSize
		}

		sp.Partitions = append(sp.Partitions, PartitionInfo{
			Name:    name,
			Size:    partSize,
			Extents: partExtents,
		})

		partOffset += int64(16 + nameSize)
	}

	return nil
}

// Close closes the super image file
func (sp *SuperImage) Close() error {
	return sp.file.Close()
}

// alignDown rounds value down to the nearest multiple
func alignDown(value, alignment int64) int64 {
	return (value / alignment) * alignment
}

// formatSize formats bytes to human-readable
func formatSize(bytes int64) string {
	const unit = 1024
	if bytes < unit {
		return fmt.Sprintf("%d B", bytes)
	}
	div, exp := int64(unit), 0
	for n := bytes / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %cB", float64(bytes)/float64(div), "KMGTPE"[exp])
}
