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
	LpMetadataGeometryMagic    = 0x504D504C
	LpMetadataHeaderMagic      = 0x484D504C
	LpMetadataGeometrySize     = 52
	LpMetadataHeaderSize       = 24
	LpMetadataExtentTypeLinear = 0
	DefaultBlockSize           = 4096
	SectorSize                 = 512
	MaxMetadataSize            = 16 * 1024 * 1024
	MaxSlotCount               = 32
	MaxGeometrySearchMB        = 64
)

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
	if err := sp.parse(); err != nil {
		f.Close()
		return nil, err
	}
	return sp, nil
}

func (sp *SuperImage) Close() error { return sp.file.Close() }

func (sp *SuperImage) parse() error {
	// The super image has metadata at the end.
	// We scan for LPMH (header) directly, without finding LPMP geometry first.
	//
	// AOSP liblp stores metadata slots at the end of the image.
	// Each slot starts with LPMH magic.
	// The geometry LPMP is also nearby.
	//
	// Approach: scan the last 64MB backwards for LPMH magic.
	// When found, parse the slot and extract partitions.

	scanStart := sp.FileSize - int64(MaxGeometrySearchMB*1024*1024)
	if scanStart < 0 {
		scanStart = 0
	}

	// We also need the geometry (LPMP) to determine metadata_max_size.
	// But actually, the metadata slot header DOES NOT contain metadata_max_size.
	// metadata_max_size is only in the LPMP geometry.
	//
	// So we need BOTH: find LPMP, then use its metadata_max_size to read LPMH.
	// This is a chicken-and-egg problem.
	//
	// Solution: find LPMP first, get metadata_max_size,
	// then find LPMH in the same region.

	// Step 1: Find LPMP (geometry)
	var geoMaxSize int64
	var geoBlockSize int64
	var geoSlotCount int
	var geoOffset int64
	geoFound := false

	sbuf := make([]byte, 4)
	for off := sp.FileSize - 4; off >= scanStart; off -= SectorSize {
		if _, err := sp.file.ReadAt(sbuf, off); err != nil {
			continue
		}
		if string(sbuf) != "LPMP" {
			continue
		}
		// Try to parse geometry
		buf := make([]byte, LpMetadataGeometrySize)
		if _, err := sp.file.ReadAt(buf, off); err != nil {
			continue
		}
		ss := binary.LittleEndian.Uint32(buf[4:8])
		mms := binary.LittleEndian.Uint32(buf[40:44])
		msc := binary.LittleEndian.Uint32(buf[44:48])
		lbs := binary.LittleEndian.Uint32(buf[48:52])

		if ss < 12 || ss > 4096 {
			continue
		}
		if mms < 512 || mms > MaxMetadataSize {
			continue
		}
		if msc < 1 || msc > MaxSlotCount {
			continue
		}

		geoMaxSize = int64(mms)
		geoBlockSize = int64(lbs)
		geoSlotCount = int(msc)
		geoOffset = off
		geoFound = true
		break
	}

	if !geoFound {
		return fmt.Errorf("no valid LPMP geometry found")
	}
	if geoBlockSize == 0 {
		geoBlockSize = DefaultBlockSize
	}

	// Step 2: Find LPMH (metadata header)
	// Search in a +/- 16MB range from the geometry.
	// AOSP stores slots before OR after the geometry depending on version.
	searchRange := int64(16 * 1024 * 1024)
	lpmhStart := geoOffset - searchRange
	if lpmhStart < 0 {
		lpmhStart = 0
	}
	lpmhEnd := geoOffset + searchRange + geoMaxSize*int64(geoSlotCount)
	if lpmhEnd > sp.FileSize {
		lpmhEnd = sp.FileSize
	}

	for off := lpmhStart; off+4 <= lpmhEnd; off += SectorSize {
		if _, err := sp.file.ReadAt(sbuf, off); err != nil {
			continue
		}
		if string(sbuf) != "LPMH" {
			continue
		}
		// Try to parse this slot
		buf := make([]byte, geoMaxSize)
		n, err := sp.file.ReadAt(buf, off)
		if err != nil && err != io.EOF {
			continue
		}
		if n < LpMetadataHeaderSize {
			continue
		}

		major := binary.LittleEndian.Uint32(buf[4:8])
		if major != 10 && major != 0 {
			continue
		}
		hdrSize := int64(binary.LittleEndian.Uint32(buf[12:16]))
		numParts := binary.LittleEndian.Uint32(buf[16:20])
		numExts := binary.LittleEndian.Uint32(buf[20:24])
		if hdrSize < LpMetadataHeaderSize {
			hdrSize = LpMetadataHeaderSize
		}
		if numParts == 0 || numParts > 256 {
			continue
		}

		// Found a valid LPMH! Parse partition table.
		sp.Partitions = nil

		// Find extent table (after all partition entries)
		extOff := hdrSize
		for i := uint32(0); i < numParts; i++ {
			if int(extOff+4) > n {
				return fmt.Errorf("part %d truncated", i)
			}
			ns := binary.LittleEndian.Uint32(buf[extOff : extOff+4])
			extOff += int64(16 + ns)
		}
		if int(extOff+32*int64(numExts)) > n {
			continue
		}

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
		partOff := hdrSize
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

	return fmt.Errorf("no valid LPMH metadata found in super image")
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
