// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jacob Paullus

package structure

import (
	"bytes"
	"encoding/binary"
)

// PackBE serialises a struct into a byte slice using Big Endian (Network Byte Order).
func PackBE(v interface{}) ([]byte, error) {
	buf := new(bytes.Buffer)
	err := binary.Write(buf, binary.BigEndian, v)
	if err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// UnpackBE deserialises a byte slice using Big Endian.
func UnpackBE(data []byte, v interface{}) error {
	buf := bytes.NewReader(data)
	return binary.Read(buf, binary.BigEndian, v)
}
