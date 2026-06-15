// Copyright 2026 soe1hom-arch
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
)

type Extractor struct {
	Input   string
	Output  string
	Verbose bool
}

func NewExtractor(input, output string) *Extractor {
	return &Extractor{Input: input, Output: output}
}

func (e *Extractor) Extract() error {
	super, err := OpenSuperImage(e.Input)
	if err != nil {
		return fmt.Errorf("failed to open super image: %w", err)
	}
	defer super.Close()

	if e.Verbose {
		fmt.Printf("Super Image: %s (%s)\n", e.Input, formatSize(super.FileSize))
		fmt.Printf("  Partitions: %d\n\n", len(super.Partitions))
	}

	if err := os.MkdirAll(e.Output, 0755); err != nil {
		return fmt.Errorf("cannot create output dir: %w", err)
	}

	extracted := 0
	for _, part := range super.Partitions {
		if e.Verbose {
			fmt.Printf("Extracting %s (%s)...\n", part.Name, formatSize(int64(part.Size)))
		}
		if err := e.extractPartition(super, part); err != nil {
			fmt.Fprintf(os.Stderr, "Warning: %s: %v\n", part.Name, err)
			continue
		}
		extracted++
	}

	if e.Verbose {
		fmt.Printf("\nExtracted %d partition(s) to %s\n", extracted, e.Output)
	}
	return nil
}

func (e *Extractor) extractPartition(super *SuperImage, part PartitionInfo) error {
	outPath := filepath.Join(e.Output, part.Name+".img")
	out, err := os.OpenFile(outPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0644)
	if err != nil {
		return fmt.Errorf("cannot create: %w", err)
	}
	defer out.Close()

	if part.Size > 0 {
		out.Truncate(int64(part.Size))
	}

	for idx, ext := range part.Extents {
		if ext.Type != LpMetadataExtentTypeLinear {
			continue
		}
		physOff := int64(ext.Sector * SectorSize)
		dataSize := int64(ext.NumSectors * SectorSize)
		if dataSize == 0 {
			continue
		}
		if _, err := out.Seek(int64(ext.PartitionSector*SectorSize), io.SeekStart); err != nil {
			return fmt.Errorf("seek: %w", err)
		}
		written, err := io.CopyN(out, io.NewSectionReader(super.file, physOff, dataSize), dataSize)
		if err != nil {
			return fmt.Errorf("extent %d: %w", idx, err)
		}
		if written != dataSize {
			return fmt.Errorf("extent %d short: %d != %d", idx, written, dataSize)
		}
	}
	return nil
}
