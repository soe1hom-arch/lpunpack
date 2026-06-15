// Copyright 2026 soe1hom-arch
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"encoding/binary"
	"fmt"
	"io"
	"os"
)

const (
	LpMetadataGeometryMagic  = 0x504D504C
	LpMetadataHeaderMagic    = 0x484D504C
	LpMetadataGeometrySize   = 52
	LpMetadataHeaderSize     = 24
	LpMetadataExtentTypeLinear = 0
	DefaultBlockSize         = 4096
	SectorSize               = 512
	MaxMetadataSize          = 16 * 1024 * 1024
	MaxSlotCount             = 32
)

type LpMetadataGeometry struct {
	Magic             [4]byte
	StructSize        uint32
	Checksum          [32]byte
	MetadataMaxSize   uint32
	MetadataSlotCount uint32
	LogicalBlockSize  uint32
}

type LpMetadataHeader struct {
	Magic         [4]byte
	MajorVersion  uint32
	MinorVersion  uint32
	HeaderSize    uint32
	NumPartitions uint32
	NumExtents    uint32
}

type LpMetadataExtent struct {
	NumSectors      uint64
	Sector          uint64
	PartitionSector uint64
	Type            uint64
}

type PartitionInfo struct {
	Name    string
	Size    uint64
	Extents []LpMetadataExtent
}

type SuperImage struct {
	Filename       string
	FileSize       int64
	Geometry       LpMetadataGeometry
	GeometryOffset int64
	Partitions     []PartitionInfo
	file           *os.File
}

func OpenSuperImage(filename string) (*SuperImage, error) {
	f, err := os.Open(filename)
	if err != nil {
		return nil, fmt.Errorf("cannot open: %w", err)
	}
	fi, err := f.Stat()
	if err != nil {
		f.Close()
		return nil, fmt.Errorf("cannot stat: %w", err)
	}
	sp := &SuperImage{Filename: filename, FileSize: fi.Size(), file: f}
	if err := sp.parseMetadata(); err != nil {
		f.Close()
		return nil, err
	}
	return sp, nil
}

func (sp *SuperImage) Close() error { return sp.file.Close() }

func (sp *SuperImage) parseMetadata() error {
	geo, offset, err := sp.findGeometry()
	if err != nil {
		return fmt.Errorf("cannot find geometry: %w", err)
	}
	sp.Geometry = *geo
	sp.GeometryOffset = offset

	maxSize := int64(geo.MetadataMaxSize)

	// Metadata slots are BEFORE the backup geometry (at the end of the image)
	// Slot 0 is nearest to the geometry, slot N-1 furthest.
	// per AOSP: slot N-1 is at geometry_offset - N * max_size
	for slot := int32(0); slot < int32(geo.MetadataSlotCount); slot++ {
		slotOffset := offset - int64(slot+1)*maxSize
		if slotOffset < 0 {
			continue
		}
		var magic [4]byte
		if _, err := sp.file.ReadAt(magic[:], slotOffset); err != nil {
			continue
		}
		if string(magic[:]) != "LPMH" {
			continue
		}
		if err := sp.readMetadataSlot(slotOffset); err == nil {
			return nil
		}
	}

	return fmt.Errorf("no valid metadata slot (LPMH) found")
}

func (sp *SuperImage) findGeometry() (*LpMetadataGeometry, int64, error) {
	addCand := func(candidates *[]int64, off int64) {
		if off >= 0 && off+LpMetadataGeometrySize <= sp.FileSize {
			for _, c := range *candidates {
				if c == off {
					return
				}
			}
			*candidates = append(*candidates, off)
		}
	}

	var candidates []int64

	// Known AOSP geometry locations:
	addCand(&candidates, sp.FileSize-4096)     // last block
	addCand(&candidates, sp.FileSize-1024)     // last 2 sectors
	addCand(&candidates, sp.FileSize-512)      // last sector
	addCand(&candidates, 0)                    // start of file
	addCand(&candidates, 512)                  // sector 1
	addCand(&candidates, 4096)                 // block 1

	// Scan the last 128KB for LPMP (step=512 for speed)
	scanStart := sp.FileSize - 128*1024
	if scanStart < 0 {
		scanStart = 0
	}
	sbuf := make([]byte, 4)
	for off := scanStart; off < sp.FileSize-4; off += 512 {
		if _, err := sp.file.ReadAt(sbuf, off); err != nil {
			break
		}
		if sbuf[0] == 'L' && sbuf[1] == 'P' && sbuf[2] == 'M' && sbuf[3] == 'P' {
			addCand(&candidates, off)
		}
	}

	for _, offset := range candidates {
		buf := make([]byte, LpMetadataGeometrySize)
		n, err := sp.file.ReadAt(buf, offset)
		if err != nil || n < LpMetadataGeometrySize {
			continue
		}
		if string(buf[0:4]) != "LPMP" {
			continue
		}

		geo := &LpMetadataGeometry{}
		copy(geo.Magic[:], buf[0:4])
		geo.StructSize = binary.LittleEndian.Uint32(buf[4:8])
		copy(geo.Checksum[:], buf[8:40])
		geo.MetadataMaxSize = binary.LittleEndian.Uint32(buf[40:44])
		geo.MetadataSlotCount = binary.LittleEndian.Uint32(buf[44:48])
		geo.LogicalBlockSize = binary.LittleEndian.Uint32(buf[48:52])

		// Sanity checks
		if geo.StructSize < 12 || geo.StructSize > 4096 {
			continue
		}
		if geo.MetadataMaxSize < 512 || geo.MetadataMaxSize > MaxMetadataSize {
			continue
		}
		if geo.MetadataSlotCount < 1 || geo.MetadataSlotCount > MaxSlotCount {
			continue
		}
		if geo.LogicalBlockSize == 0 || geo.LogicalBlockSize > 65536 {
			geo.LogicalBlockSize = DefaultBlockSize
		}

		return geo, offset, nil
	}

	return nil, 0, fmt.Errorf("no valid LPMP geometry found")
}

func (sp *SuperImage) readMetadataSlot(offset int64) error {
	maxSize := int64(sp.Geometry.MetadataMaxSize)
	buf := make([]byte, maxSize)
	n, err := sp.file.ReadAt(buf, offset)
	if err != nil && err != io.EOF {
		return fmt.Errorf("read slot: %w", err)
	}
	if n < LpMetadataHeaderSize {
		return fmt.Errorf("slot too small: %d", n)
	}

	magic := string(buf[0:4])
	if magic != "LPMH" {
		return fmt.Errorf("bad magic: %s", magic)
	}
	majorVer := binary.LittleEndian.Uint32(buf[4:8])
	if majorVer != 10 {
		return fmt.Errorf("unsupported version: %d", majorVer)
	}

	headerSize := int64(binary.LittleEndian.Uint32(buf[12:16]))
	numParts := binary.LittleEndian.Uint32(buf[16:20])
	numExts := binary.LittleEndian.Uint32(buf[20:24])

	if headerSize < LpMetadataHeaderSize {
		headerSize = LpMetadataHeaderSize
	}
	if int(headerSize) >= n {
		return fmt.Errorf("header beyond buffer")
	}

	// Find extent table location (after all partition entries)
	extOff := headerSize
	for i := uint32(0); i < numParts; i++ {
		if int(extOff+4) > n {
			return fmt.Errorf("truncated part %d", i)
		}
		ns := binary.LittleEndian.Uint32(buf[extOff : extOff+4])
		extOff += int64(16 + ns)
	}

	if int(extOff+32*int64(numExts)) > n {
		return fmt.Errorf("truncated extents")
	}

	// Read extents
	extents := make([]LpMetadataExtent, numExts)
	for i := uint32(0); i < numExts; i++ {
		es := extOff + int64(i)*32
		extents[i] = LpMetadataExtent{
			NumSectors:      binary.LittleEndian.Uint64(buf[es : es+8]),
			Sector:          binary.LittleEndian.Uint64(buf[es+8 : es+16]),
			PartitionSector: binary.LittleEndian.Uint64(buf[es+16 : es+24]),
			Type:            binary.LittleEndian.Uint64(buf[es+24 : es+32]),
		}
	}

	// Read partitions
	partOff := headerSize
	for i := uint32(0); i < numParts; i++ {
		if int(partOff+16) > n {
			break
		}
		ns := binary.LittleEndian.Uint32(buf[partOff : partOff+4])
		attr := binary.LittleEndian.Uint32(buf[partOff+4 : partOff+8])
		fi := binary.LittleEndian.Uint32(buf[partOff+8 : partOff+12])
		ne := binary.LittleEndian.Uint32(buf[partOff+12 : partOff+16])

		var name string
		if ns > 0 {
			end := partOff + 16 + int64(ns)
			if int(end) <= n {
				nb := buf[partOff+16 : end]
				for j := 0; j < len(nb); j++ {
					if nb[j] == 0 {
						nb = nb[:j]
						break
					}
				}
				name = string(nb)
			}
		}
		_ = attr

		var pSize uint64
		var pExt []LpMetadataExtent
		for j := fi; j < fi+ne && j < uint32(len(extents)); j++ {
			pExt = append(pExt, extents[j])
			pSize += extents[j].NumSectors * SectorSize
		}

		sp.Partitions = append(sp.Partitions, PartitionInfo{
			Name: name, Size: pSize, Extents: pExt,
		})
		partOff += int64(16 + ns)
	}

	return nil
}

func formatSize(b int64) string {
	const u = 1024
	if b < u {
		return fmt.Sprintf("%d B", b)
	}
	d, e := int64(u), 0
	for n := b / u; n >= u; n /= u {
		d *= u
		e++
	}
	return fmt.Sprintf("%.1f %cB", float64(b)/float64(d), "KMGTPE"[e])
}
