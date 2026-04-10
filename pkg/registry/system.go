// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jacob Paullus

package registry

import (
	"encoding/hex"
	"fmt"
	"strings"
)

// Boot key permutation table
var bootKeyPermutation = []int{8, 5, 4, 2, 11, 9, 13, 3, 0, 6, 1, 12, 14, 10, 15, 7}

// GetBootKey extracts the boot key from a SYSTEM hive
// The boot key is scrambled across the class names of JD, Skew1, GBG, Data keys
func GetBootKey(systemHive *Hive) ([]byte, error) {
	// Determine current control set
	controlSet, err := GetCurrentControlSet(systemHive)
	if err != nil {
		return nil, fmt.Errorf("failed to get current control set: %v", err)
	}

	// Boot key is derived from class names of these 4 keys
	keyNames := []string{"JD", "Skew1", "GBG", "Data"}
	var bootKeyParts []byte

	for _, keyName := range keyNames {
		path := fmt.Sprintf("%s\\Control\\Lsa\\%s", controlSet, keyName)

		keyOffset, err := systemHive.FindKey(path)
		if err != nil {
			return nil, fmt.Errorf("failed to find %s: %v", path, err)
		}

		className, err := systemHive.GetClassName(keyOffset)
		if err != nil {
			return nil, fmt.Errorf("failed to get class name for %s: %v", path, err)
		}

		bootKeyParts = append(bootKeyParts, []byte(className)...)
	}

	// Descramble the boot key
	return descrambleBootKey(bootKeyParts)
}

// GetCurrentControlSet determines which ControlSet is currently in use
func GetCurrentControlSet(systemHive *Hive) (string, error) {
	// Find Select key
	selectOffset, err := systemHive.FindKey("Select")
	if err != nil {
		return "", fmt.Errorf("failed to find Select key: %v", err)
	}

	// Read "Current" value
	_, data, err := systemHive.GetValue(selectOffset, "Current")
	if err != nil {
		return "", fmt.Errorf("failed to read Current value: %v", err)
	}

	if len(data) < 4 {
		return "", fmt.Errorf("invalid Current value")
	}

	current := uint32(data[0]) | uint32(data[1])<<8 | uint32(data[2])<<16 | uint32(data[3])<<24
	return fmt.Sprintf("ControlSet%03d", current), nil
}

// descrambleBootKey descrambles the boot key from class name parts
func descrambleBootKey(scrambled []byte) ([]byte, error) {
	// Class names are hex encoded, concatenated = 32 hex chars = 16 bytes
	scrambledStr := strings.ToLower(string(scrambled))
	if len(scrambledStr) != 32 {
		return nil, fmt.Errorf("invalid boot key parts length: %d (expected 32)", len(scrambledStr))
	}

	decoded, err := hex.DecodeString(scrambledStr)
	if err != nil {
		return nil, fmt.Errorf("failed to decode boot key: %v", err)
	}

	if len(decoded) != 16 {
		return nil, fmt.Errorf("invalid decoded boot key length: %d", len(decoded))
	}

	// Apply permutation
	bootKey := make([]byte, 16)
	for i := 0; i < 16; i++ {
		bootKey[i] = decoded[bootKeyPermutation[i]]
	}

	return bootKey, nil
}

// GetComputerName retrieves the computer name from the SYSTEM hive
func GetComputerName(systemHive *Hive) (string, error) {
	controlSet, err := GetCurrentControlSet(systemHive)
	if err != nil {
		return "", err
	}

	path := fmt.Sprintf("%s\\Control\\ComputerName\\ComputerName", controlSet)
	keyOffset, err := systemHive.FindKey(path)
	if err != nil {
		return "", err
	}

	_, data, err := systemHive.GetValue(keyOffset, "ComputerName")
	if err != nil {
		return "", err
	}

	// Value is REG_SZ (UTF-16LE with null terminator)
	return decodeUTF16String(data), nil
}

// decodeUTF16String decodes a UTF-16LE string
func decodeUTF16String(data []byte) string {
	if len(data) < 2 {
		return ""
	}

	// Convert to uint16 slice
	chars := make([]uint16, len(data)/2)
	for i := 0; i < len(chars); i++ {
		chars[i] = uint16(data[i*2]) | uint16(data[i*2+1])<<8
	}

	// Trim null terminator
	for len(chars) > 0 && chars[len(chars)-1] == 0 {
		chars = chars[:len(chars)-1]
	}

	// Decode UTF-16
	runes := make([]rune, len(chars))
	for i, c := range chars {
		runes[i] = rune(c)
	}

	return string(runes)
}
