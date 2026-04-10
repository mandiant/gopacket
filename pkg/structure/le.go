// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jacob Paullus

package structure

import (
	"bytes"
	"encoding/binary"
)

// PackLE serialises a struct into a byte slice using Little Endian.
func PackLE(v interface{}) ([]byte, error) {
	buf := new(bytes.Buffer)
	err := binary.Write(buf, binary.LittleEndian, v)
	if err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// UnpackLE deserialises a byte slice into a struct using Little Endian.
func UnpackLE(data []byte, v interface{}) error {
	buf := bytes.NewReader(data)
	return binary.Read(buf, binary.LittleEndian, v)
}
