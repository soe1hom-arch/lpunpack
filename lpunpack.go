// Copyright 2026 soe1hom-arch
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
)

// Extractor handles partition extraction from super image
type Extractor struct {
	Input   string
	Output  string
	Verbose bool
}

// NewExtractor creates a new extractor
func NewExtractor(input, output string) *Extractor {
	return &Extractor{
		Input:   input,
		Output:  output,
	}
}

// Extract extracts all partitions from the super image
func (e *Extractor) Extract() error {
	super, err := OpenSuperImage(e.Input)
	if err != nil {
		return fmt.Errorf("failed to open super image: %w", err)
	}
	defer super.Close()

	if e.Verbose {
		fmt.Printf("Super Image: %s (%d bytes)\n", e.Input, super.FileSize)
		fmt.Printf("  Block Size: %d\n", super.Geometry.LogicalBlockSize)
		fmt.Printf("  Metadata Slots: %d\n", super.Geometry.MetadataSlotCount)
		fmt.Printf("  Partitions: %d\n\n", len(super.Partitions))
	}

	// Create output directory
	if err := os.MkdirAll(e.Output, 0755); err != nil {
		return fmt.Errorf("cannot create output directory: %w", err)
	}

	extracted := 0
	for _, part := range super.Partitions {
		if e.Verbose {
			fmt.Printf("Extracting %s (%s)...\n", part.Name, formatSize(int64(part.Size)))
		}

		if err := e.extractPartition(super, part); err != nil {
			fmt.Fprintf(os.Stderr, "Warning: failed to extract %s: %v\n", part.Name, err)
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
	outputPath := filepath.Join(e.Output, part.Name+".img")

	outFile, err := os.OpenFile(outputPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0644)
	if err != nil {
		return fmt.Errorf("cannot create output file: %w", err)
	}
	defer outFile.Close()

	// Pre-allocate
	if part.Size > 0 {
		outFile.Truncate(int64(part.Size))
	}

	for idx, ext := range part.Extents {
		if ext.Type != LpMetadataExtentTypeLinear {
			if e.Verbose {
				fmt.Fprintf(os.Stderr, "  Warning: extent %d has unknown type %d, skipping\n", idx, ext.Type)
			}
			continue
		}

		// Calculate byte offsets
		physicalOffset := ext.Sector * SectorSize
		dataSize := ext.NumSectors * SectorSize

		if dataSize == 0 {
			continue
		}

		// Read from super image and write to output
		if _, err := outFile.Seek(int64(ext.PartitionSector*SectorSize), io.SeekStart); err != nil {
			return fmt.Errorf("cannot seek in output: %w", err)
		}

		written, err := io.CopyN(outFile, io.NewSectionReader(super.file, int64(physicalOffset), int64(dataSize)), int64(dataSize))
		if err != nil {
			return fmt.Errorf("failed to copy extent %d: %w", idx, err)
		}
		if uint64(written) != dataSize {
			return fmt.Errorf("short write for extent %d: %d != %d", idx, written, dataSize)
		}
	}

	return nil
}
