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
	ChunkSize                  = 1024 * 1024 // 1MB chunks
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

func (sp *SuperImage) parse() error {
	var candidates []struct {
		offset int64
		magic  string
	}

	// Scan ENTIRE file for LPMH and LPMP in 1MB chunks
	if sp.Verbose {
		fmt.Printf("Scanning %d bytes in %dKB chunks...\n", sp.FileSize, ChunkSize/1024)
	}

	for off := int64(0); off < sp.FileSize; off += ChunkSize {
		readSize := int64(ChunkSize)
		remaining := sp.FileSize - off
		if remaining < readSize {
			readSize = remaining
		}
		buf := make([]byte, readSize)
		n, err := sp.file.ReadAt(buf, off)
		if err != nil && err != io.EOF {
			continue
		}
		data := buf[:n]

		for _, pattern := range [][]byte{{'L', 'P', 'M', 'H'}, {'L', 'P', 'M', 'P'}} {
			idx := 0
			for {
				pos := bytes.Index(data[idx:], pattern)
				if pos < 0 {
					break
				}
				candidates = append(candidates, struct {
					offset int64
					magic  string
				}{offset: off + int64(idx+pos), magic: string(pattern)})
				idx += pos + 1
			}
		}

		if sp.Verbose && off%(100*ChunkSize) == 0 {
			fmt.Printf("  scanned %d MB so far...\n", off/1024/1024)
		}
	}

	if sp.Verbose {
		fmt.Printf("Found %d magic signatures across entire file\n", len(candidates))
		// Group by magic
		lpmhCount := 0
		lpmpCount := 0
		for _, c := range candidates {
			if c.magic == "LPMH" {
				lpmhCount++
			} else {
				lpmpCount++
			}
		}
		fmt.Printf("  LPMH: %d, LPMP: %d\n", lpmhCount, lpmpCount)
		if lpmhCount > 0 {
			fmt.Println("LPMH locations:")
			for _, c := range candidates {
				if c.magic == "LPMH" {
					fmt.Printf("  offset %d (%.2f MB from start, %.2f MB from end)\n",
						c.offset,
						float64(c.offset)/1024/1024,
						float64(sp.FileSize-c.offset)/1024/1024)
				}
			}
		}
	}

	// Extract metadata_max_size from LPMP candidates
	var bufSize int64 = 16 * 1024 * 1024
	lpmpValid := 0
	for _, c := range candidates {
		if c.magic != "LPMP" {
			continue
		}
		buf := make([]byte, 52)
		if _, err := sp.file.ReadAt(buf, c.offset); err != nil {
			continue
		}
		ss := binary.LittleEndian.Uint32(buf[4:8])
		mms := binary.LittleEndian.Uint32(buf[40:44])
		msc := binary.LittleEndian.Uint32(buf[44:48])
		lbs := binary.LittleEndian.Uint32(buf[48:52])
		if ss >= 12 && ss <= 4096 && mms >= 512 && mms <= MaxBuf && msc >= 1 && msc <= 32 {
			bufSize = int64(mms)
			lpmpValid++
			if sp.Verbose {
				fmt.Printf("  Valid LPMP@%d: structSize=%d maxSize=%d slots=%d blockSize=%d\n",
					c.offset, ss, mms, msc, lbs)
			}
		}
	}
	if sp.Verbose && lpmpValid > 0 {
		fmt.Printf("Using bufSize=%d from LPMP\n", bufSize)
	} else if sp.Verbose {
		fmt.Println("No valid LPMP found, using default bufSize=16MB")
	}

	// Try to parse each LPMH
	for _, c := range candidates {
		if c.magic != "LPMH" {
			continue
		}

		buf := make([]byte, bufSize)
		n, err := sp.file.ReadAt(buf, c.offset)
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
			fmt.Printf("  LPMH@%d: v%d.%d hdrSize=%d parts=%d exts=%d\n",
				c.offset, major, minor, hdrSz, numParts, numExts)
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

		extOff := hs
		for i := uint32(0); i < numParts; i++ {
			if int(extOff+4) > n {
				return fmt.Errorf("part %d truncated at %d", i, extOff)
			}
			ns := binary.LittleEndian.Uint32(buf[extOff : extOff+4])
			if ns > 256 {
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
			if extents[i].NumSectors == 0 && extents[i].Type == LpMetadataExtentTypeLinear {
				extOff = -1
				break
			}
		}
		if extOff < 0 {
			continue
		}

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
				fmt.Printf("  ✅ %d partitions found!\n", len(sp.Partitions))
			}
			return nil
		}
	}

	return fmt.Errorf("no valid partition table found (scanned entire %d byte file, %d magic hits)", sp.FileSize, len(candidates))
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
