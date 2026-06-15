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
	ScanMB                     = 256
	ChunkSize                  = 256 * 1024
	MaxBuf                     = 64 * 1024 * 1024
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
	Verbose    bool
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

type foundMagic struct {
	offset int64
	magic  string
	err    string
}

func (sp *SuperImage) scanRange(start, size int64) []foundMagic {
	var result []foundMagic
	seen := make(map[int64]bool)

	end := start + size
	if end > sp.FileSize {
		end = sp.FileSize
	}
	if start < 0 {
		start = 0
	}

	for off := start; off < end; off += ChunkSize {
		readSize := int64(ChunkSize)
		if off+readSize > end {
			readSize = end - off
		}
		buf := make([]byte, readSize)
		n, err := sp.file.ReadAt(buf, off)
		if err != nil && err != io.EOF {
			continue
		}
		data := buf[:n]

		for _, magic := range [][]byte{{'L', 'P', 'M', 'H'}, {'L', 'P', 'M', 'P'}} {
			idx := 0
			for {
				pos := bytes.Index(data[idx:], magic)
				if pos < 0 {
					break
				}
				absOff := off + int64(idx+pos)
				if !seen[absOff] {
					result = append(result, foundMagic{offset: absOff, magic: string(magic)})
					seen[absOff] = true
				}
				idx += pos + 1
			}
		}
	}
	return result
}

func (sp *SuperImage) parse() error {
	// Scan BOTH ends of the file for magic bytes
	scanSize := int64(ScanMB * 1024 * 1024)
	slots := sp.scanRange(0, scanSize)                       // start
	slots = append(slots, sp.scanRange(sp.FileSize-scanSize, scanSize)...) // end

	if len(slots) == 0 {
		return fmt.Errorf("no LPMP/LPMH found (scanned first+last %dMB of %d byte file)", ScanMB, sp.FileSize)
	}

	if sp.Verbose {
		fmt.Printf("Found %d magic signatures:\n", len(slots))
		for _, s := range slots {
			fmt.Printf("  %s at byte %d (0x%x)\n", s.magic, s.offset, s.offset)
		}
	}

	// Extract metadata_max_size from LPMP candidates
	var bufSize int64 = 16 * 1024 * 1024 // 16MB default
	for _, s := range slots {
		if s.magic != "LPMP" {
			continue
		}
		buf := make([]byte, 52)
		if _, err := sp.file.ReadAt(buf, s.offset); err != nil {
			continue
		}
		ss := binary.LittleEndian.Uint32(buf[4:8])
		mms := binary.LittleEndian.Uint32(buf[40:44])
		msc := binary.LittleEndian.Uint32(buf[44:48])
		lbs := binary.LittleEndian.Uint32(buf[48:52])
		if ss >= 12 && ss <= 4096 && mms >= 512 && mms <= MaxBuf && msc >= 1 && msc <= 32 {
			bufSize = int64(mms)
			if sp.Verbose {
				fmt.Printf("  Using LPMP@%d: maxSize=%d slots=%d blockSize=%d\n", s.offset, mms, msc, lbs)
			}
		}
	}

	// Try to parse each LPMH
	for _, s := range slots {
		if s.magic != "LPMH" {
			continue
		}

		buf := make([]byte, bufSize)
		n, err := sp.file.ReadAt(buf, s.offset)
		if err != nil && err != io.EOF {
			continue
		}
		if n < 24 {
			continue
		}

		major := binary.LittleEndian.Uint32(buf[4:8])
		minor := binary.LittleEndian.Uint32(buf[8:12])
		hdrSz := binary.LittleEndian.Uint32(buf[12:16])
		numParts := binary.LittleEndian.Uint32(buf[16:20])
		numExts := binary.LittleEndian.Uint32(buf[20:24])

		if sp.Verbose {
			fmt.Printf("  Trying LPMH@%d: v%d.%d hdrSize=%d parts=%d exts=%d\n",
				s.offset, major, minor, hdrSz, numParts, numExts)
		}

		if major != 10 && major != 0 {
			continue
		}
		if numParts < 1 || numParts > 256 {
			continue
		}
		if numExts > 65536 {
			continue
		}

		hs := int64(hdrSz)
		if hs < 24 {
			hs = 24
		}
		if int(hs) >= n {
			continue
		}

		// Validate structure before parsing
		extOff := hs
		for i := uint32(0); i < numParts; i++ {
			if int(extOff+4) > n {
				return fmt.Errorf("LPMH@%d: part %d truncated at buf offset %d", s.offset, i, extOff)
			}
			ns := binary.LittleEndian.Uint32(buf[extOff : extOff+4])
			if ns > 256 { // sanity check on name size
				if sp.Verbose {
					fmt.Printf("    skip: part %d nameSize=%d too large\n", i, ns)
				}
				extOff = -1
				break
			}
			extOff += int64(16 + ns)
		}
		if extOff < 0 {
			continue
		}

		needExt := extOff + 32*int64(numExts)
		if int(needExt) > n {
			if sp.Verbose {
				fmt.Printf("    skip: extents need %d bytes but buffer is %d\n", needExt, n)
			}
			continue
		}

		// Parse extents
		extents := make([]LpMetadataExtent, numExts)
		for i := uint32(0); i < numExts; i++ {
			es := extOff + int64(i)*32
			extents[i] = LpMetadataExtent{
				NumSectors:      binary.LittleEndian.Uint64(buf[es : es+8]),
				Sector:          binary.LittleEndian.Uint64(buf[es+8 : es+16]),
				PartitionSector: binary.LittleEndian.Uint64(buf[es+16 : es+24]),
				Type:            binary.LittleEndian.Uint64(buf[es+24 : es+32]),
			}
			// Validate extent
			if extents[i].NumSectors == 0 && extents[i].Type == LpMetadataExtentTypeLinear {
				if sp.Verbose {
					fmt.Printf("    skip: extent %d has 0 sectors\n", i)
				}
				extOff = -1
				break
			}
		}
		if extOff < 0 {
			continue
		}

		// Parse partitions
		sp.Partitions = nil
		partOff := hs
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
			if sp.Verbose {
				fmt.Printf("  ✅ Success! Got %d partitions\n", len(sp.Partitions))
				for _, p := range sp.Partitions {
					fmt.Printf("     %s (%s)\n", p.Name, formatSize(int64(p.Size)))
				}
			}
			return nil
		}
	}

	return fmt.Errorf("no valid partition table found (%d magic hits in first+last %dMB)", len(slots), ScanMB)
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
