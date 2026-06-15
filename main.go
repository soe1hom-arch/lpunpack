// Copyright 2026 soe1hom-arch
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"fmt"
	"os"
)

func main() {
	verbose := false

	// Simple arg parsing — match original lpunpack behavior
	args := os.Args[1:]
	for i := 0; i < len(args); i++ {
		if args[i] == "-v" || args[i] == "--verbose" {
			verbose = true
			args = append(args[:i], args[i+1:]...)
			i--
		}
	}

	if len(args) < 1 || len(args) > 2 {
		usage()
	}

	input := args[0]
	output := "."
	if len(args) >= 2 {
		output = args[1]
	}

	// Validate input
	if _, err := os.Stat(input); os.IsNotExist(err) {
		fmt.Fprintf(os.Stderr, "Error: input file does not exist: %s\n", input)
		os.Exit(1)
	}

	// Validate output directory (create if not exists)
	if _, err := os.Stat(output); os.IsNotExist(err) {
		if err := os.MkdirAll(output, 0755); err != nil {
			fmt.Fprintf(os.Stderr, "Error: cannot create output directory: %s\n", output)
			os.Exit(1)
		}
	}

	extractor := NewExtractor(input, output)
	extractor.Verbose = verbose

	if err := extractor.Extract(); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}

func usage() {
	fmt.Fprintf(os.Stderr, "Usage: %s <super_image> [output_directory]\n", os.Args[0])
	fmt.Fprintf(os.Stderr, "\nExtract partitions from Android super image\n")
	fmt.Fprintf(os.Stderr, "\nArguments:\n")
	fmt.Fprintf(os.Stderr, "  <super_image>      Path to super.img\n")
	fmt.Fprintf(os.Stderr, "  [output_directory] Output directory (default: current dir)\n")
	fmt.Fprintf(os.Stderr, "\nOptions:\n")
	fmt.Fprintf(os.Stderr, "  -v, --verbose      Show detailed output\n")
	os.Exit(1)
}
