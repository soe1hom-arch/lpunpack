// Copyright 2026 soe1hom-arch
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"os"
)

const (
	LpMetadataExtentTypeLinear = 0
	SectorSize                 = 512
	ScanMB                     = 256 // scan last 256MB
	ChunkSize                  = 512 * 1024
	DefaultBufSize             = 4 * 1024 * 1024
	MaxBufSize                 = 64 * 1024 * 1024
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
	Filename   string
	FileSize   int64
	Partitions []PartitionInfo
	file       *os.File
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
	// Read large chunks from the end and search for LPMP + LPMH in memory.
	// This is much faster and catches magic at ANY byte offset.

	scanStart := sp.FileSize - int64(ScanMB*1024*1024)
	if scanStart < 0 {
		scanStart = 0
	}

	type slot struct {
		offset int64
		isLPMP bool
	}
	var slots []slot
	seen := make(map[int64]bool)

	// Read last ScanMB in chunks
	for off := scanStart; off < sp.FileSize; off += ChunkSize {
		buf := make([]byte, ChunkSize)
		n, err := sp.file.ReadAt(buf, off)
		if err != nil && err != io.EOF {
			continue
		}
		data := buf[:n]

		// Search for magic bytes at any position
		for _, magic := range [][]byte{
			{'L', 'P', 'M', 'H'},
			{'L', 'P', 'M', 'P'},
		} {
			idx := 0
			for {
				pos := bytes.Index(data[idx:], magic)
				if pos < 0 {
					break
				}
				absOff := off + int64(idx+pos)
				if !seen[absOff] {
					slots = append(slots, slot{offset: absOff, isLPMP: magic[3] == 'P'})
					seen[absOff] = true
				}
				idx += pos + 1
			}
		}
	}

	// Extract metadata_max_sizes from any LPMP found
	var maxSizes []int64
	for _, s := range slots {
		if !s.isLPMP {
			continue
		}
		buf := make([]byte, 52)
		if _, err := sp.file.ReadAt(buf, s.offset); err != nil {
			continue
		}
		ss := binary.LittleEndian.Uint32(buf[4:8])
		mms := binary.LittleEndian.Uint32(buf[40:44])
		msc := binary.LittleEndian.Uint32(buf[44:48])
		if ss >= 12 && ss <= 4096 && mms >= 512 && mms <= MaxBufSize && msc >= 1 && msc <= 32 {
			maxSizes = append(maxSizes, int64(mms))
		}
	}

	// Try parse each LPMH slot
	for _, s := range slots {
		if s.isLPMP {
			continue
		}

		// Build list of buffer sizes to try
		trySizes := []int64{DefaultBufSize}
		for _, ms := range maxSizes {
			trySizes = append(trySizes, ms)
		}
		trySizes = append(trySizes, MaxBufSize)

		seenSz := make(map[int64]bool)
		for _, bufSize := range trySizes {
			if seenSz[bufSize] {
				continue
			}
			seenSz[bufSize] = true

			buf := make([]byte, bufSize)
			n, err := sp.file.ReadAt(buf, s.offset)
			if err != nil && err != io.EOF {
				continue
			}
			if n < 24 {
				continue
			}
			if string(buf[0:4]) != "LPMH" {
				continue
			}

			major := binary.LittleEndian.Uint32(buf[4:8])
			hdrSize := int64(binary.LittleEndian.Uint32(buf[12:16]))
			numParts := binary.LittleEndian.Uint32(buf[16:20])
			numExts := binary.LittleEndian.Uint32(buf[20:24])

			if major != 10 && major != 0 {
				continue
			}
			if hdrSize < 24 {
				hdrSize = 24
			}
			if numParts == 0 || numParts > 256 {
				continue
			}
			if int(hdrSize) >= n {
				continue
			}

			extOff := hdrSize
			for i := uint32(0); i < numParts; i++ {
				if int(extOff+4) > n {
					extOff = -1
					break
				}
				ns := binary.LittleEndian.Uint32(buf[extOff : extOff+4])
				extOff += int64(16 + ns)
			}
			if extOff < 0 {
				continue
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

			sp.Partitions = nil
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

			if len(sp.Partitions) > 0 {
				return nil
			}
		}
	}

	return fmt.Errorf("no valid partition table found in super image (scanned last %dMB)", ScanMB)
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
