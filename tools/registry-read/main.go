// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jacob Paullus

package main

import (
	"encoding/binary"
	"flag"
	"fmt"
	"os"
	"path"
	"strings"
	"unicode/utf16"

	"gopacket/pkg/registry"
)

const (
	REG_SZ        = 0x01
	REG_EXPAND_SZ = 0x02
	REG_BINARY    = 0x03
	REG_DWORD     = 0x04
	REG_MULTISZ   = 0x07
	REG_QWORD     = 0x0b
	REG_NONE      = 0x00
)

func main() {
	if len(os.Args) < 3 {
		usage()
		os.Exit(1)
	}

	hiveFile := os.Args[1]
	command := strings.ToLower(os.Args[2])

	// Parse subcommand flags
	subFlags := flag.NewFlagSet(command, flag.ExitOnError)
	name := subFlags.String("name", "", "registry key/value path")
	recursive := subFlags.Bool("recursive", false, "recursive enumeration")
	subFlags.Parse(os.Args[3:])

	if *name == "" {
		fmt.Fprintf(os.Stderr, "Error: -name is required\n")
		os.Exit(1)
	}

	data, err := os.ReadFile(hiveFile)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error reading hive: %v\n", err)
		os.Exit(1)
	}

	hive, err := registry.Open(data)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error opening hive: %v\n", err)
		os.Exit(1)
	}

	switch command {
	case "enum_key":
		cmdEnumKey(hive, *name, *recursive)
	case "enum_values":
		cmdEnumValues(hive, *name)
	case "get_value":
		cmdGetValue(hive, *name)
	case "get_class":
		cmdGetClass(hive, *name)
	case "walk":
		cmdWalk(hive, *name)
	default:
		fmt.Fprintf(os.Stderr, "Unknown command: %s\n", command)
		usage()
		os.Exit(1)
	}
}

func usage() {
	fmt.Fprintf(os.Stderr, "Usage: %s <hive_file> <command> [flags]\n\n", os.Args[0])
	fmt.Fprintf(os.Stderr, "Commands:\n")
	fmt.Fprintf(os.Stderr, "  enum_key     -name PATH [-recursive]\n")
	fmt.Fprintf(os.Stderr, "  enum_values  -name PATH\n")
	fmt.Fprintf(os.Stderr, "  get_value    -name PATH\\VALUENAME\n")
	fmt.Fprintf(os.Stderr, "  get_class    -name PATH\n")
	fmt.Fprintf(os.Stderr, "  walk         -name PATH\n")
}

func stripLeadingSlash(p string) string {
	if len(p) > 1 && p[0] == '\\' {
		return p[1:]
	}
	return p
}

func cmdEnumKey(hive *registry.Hive, name string, recursive bool) {
	fmt.Printf("[%s]\n", name)

	keyPath := stripLeadingSlash(name)
	offset, err := hive.FindKey(keyPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}

	enumKeyRecursive(hive, offset, "  ", recursive)
}

func enumKeyRecursive(hive *registry.Hive, keyOffset int32, indent string, recursive bool) {
	subKeys, err := hive.EnumSubKeys(keyOffset)
	if err != nil {
		return
	}

	for _, sk := range subKeys {
		fmt.Printf("%s%s\n", indent, sk)
		if recursive {
			// Find the subkey offset
			nk, err := hive.FindSubKey(keyOffset, sk)
			if err != nil {
				continue
			}
			enumKeyRecursive(hive, nk, indent+"  ", recursive)
		}
	}
}

func cmdEnumValues(hive *registry.Hive, name string) {
	keyPath := stripLeadingSlash(name)
	offset, err := hive.FindKey(keyPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("[%s]\n\n", name)

	values, err := hive.EnumValues(offset)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}

	// Print value name list in Python b'' format
	var bNames []string
	for _, v := range values {
		bNames = append(bNames, fmt.Sprintf("b'%s'", v))
	}
	fmt.Printf("[%s]\n", strings.Join(bNames, ", "))

	// Print each value
	for _, v := range values {
		valType, valData, err := hive.GetValue(offset, v)
		if err != nil {
			continue
		}

		bName := fmt.Sprintf("b'%s'", v)
		fmt.Printf("  %-30s: ", bName)

		if valType == REG_BINARY {
			fmt.Print(" \n")
			fmt.Println()
			hexDump(valData, "")
			fmt.Println()
		} else {
			fmt.Print(" ")
			printValue(valType, valData)
		}
	}
}

func cmdGetValue(hive *registry.Hive, name string) {
	// Split into key path and value name using last backslash
	keyPath := stripLeadingSlash(name)
	regKey := path.Dir(strings.ReplaceAll(keyPath, "\\", "/"))
	regKey = strings.ReplaceAll(regKey, "/", "\\")
	regValue := path.Base(strings.ReplaceAll(keyPath, "\\", "/"))

	// Display path uses the directory portion with leading backslash
	displayDir := path.Dir(strings.ReplaceAll(name, "\\", "/"))
	displayDir = strings.ReplaceAll(displayDir, "/", "\\")

	offset, err := hive.FindKey(regKey)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("[%s]\n\n", displayDir)

	valType, valData, err := hive.GetValue(offset, regValue)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("Value for %s:\n     ", regValue)
	printValue(valType, valData)
}

func cmdGetClass(hive *registry.Hive, name string) {
	keyPath := stripLeadingSlash(name)
	regKey := path.Dir(strings.ReplaceAll(keyPath, "\\", "/"))
	regKey = strings.ReplaceAll(regKey, "/", "\\")
	className := path.Base(strings.ReplaceAll(keyPath, "\\", "/"))

	displayDir := path.Dir(strings.ReplaceAll(name, "\\", "/"))
	displayDir = strings.ReplaceAll(displayDir, "/", "\\")

	offset, err := hive.FindKey(keyPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}

	rawClass, err := hive.GetClassNameRaw(offset)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}

	if rawClass == nil {
		return
	}

	fmt.Printf("[%s]\n", displayDir)
	fmt.Printf("Value for Class %s: \n ", className)
	hexDump(rawClass, "   ")
}

func cmdWalk(hive *registry.Hive, name string) {
	keyPath := stripLeadingSlash(name)
	offset, err := hive.FindKey(keyPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}

	walkRecursive(hive, offset, "")
}

func walkRecursive(hive *registry.Hive, keyOffset int32, indent string) {
	subKeys, err := hive.EnumSubKeys(keyOffset)
	if err != nil {
		return
	}

	for _, sk := range subKeys {
		fmt.Printf("%s%s\n", indent, sk)
		nk, err := hive.FindSubKey(keyOffset, sk)
		if err != nil {
			continue
		}
		walkRecursive(hive, nk, indent+"  ")
	}
}

func printValue(valType uint32, data []byte) {
	switch valType {
	case REG_DWORD:
		if len(data) >= 4 {
			v := binary.LittleEndian.Uint32(data)
			fmt.Printf("%d\n", v)
		}
	case REG_QWORD:
		if len(data) >= 8 {
			v := binary.LittleEndian.Uint64(data)
			fmt.Printf("%d\n", v)
		}
	case REG_SZ, REG_EXPAND_SZ, REG_MULTISZ:
		s := decodeUTF16Raw(data)
		fmt.Printf("%s\n", s)
	case REG_BINARY:
		fmt.Println()
		hexDump(data, "")
	case REG_NONE:
		if len(data) > 1 {
			fmt.Println()
			hexDump(data, "")
		} else {
			fmt.Println(" NULL")
		}
	default:
		fmt.Printf("Unknown Type 0x%x!\n", valType)
		hexDump(data, "")
	}
}

func decodeUTF16(data []byte) string {
	if len(data) < 2 {
		return ""
	}
	chars := make([]uint16, len(data)/2)
	for i := range chars {
		chars[i] = binary.LittleEndian.Uint16(data[i*2:])
	}
	// Trim trailing nulls
	for len(chars) > 0 && chars[len(chars)-1] == 0 {
		chars = chars[:len(chars)-1]
	}
	return string(utf16.Decode(chars))
}

// decodeUTF16Raw decodes UTF-16LE without stripping nulls (matches Impacket behavior)
func decodeUTF16Raw(data []byte) string {
	if len(data) < 2 {
		return ""
	}
	chars := make([]uint16, len(data)/2)
	for i := range chars {
		chars[i] = binary.LittleEndian.Uint16(data[i*2:])
	}
	return string(utf16.Decode(chars))
}

func hexDump(data []byte, indent string) {
	for i := 0; i < len(data); i += 16 {
		// Format: " %s%04x   " then hex bytes then "  " then ASCII
		line := fmt.Sprintf(" %s%04x   ", indent, i)

		// Hex bytes
		for j := 0; j < 16; j++ {
			if i+j < len(data) {
				line += fmt.Sprintf("%02X ", data[i+j])
			} else {
				line += "   "
			}
			if j == 7 {
				line += " "
			}
		}

		// ASCII
		line += "  "
		for j := 0; j < 16 && i+j < len(data); j++ {
			b := data[i+j]
			if b >= 0x20 && b <= 0x7e {
				line += string(rune(b))
			} else {
				line += "."
			}
		}

		fmt.Println(line)
	}
}
