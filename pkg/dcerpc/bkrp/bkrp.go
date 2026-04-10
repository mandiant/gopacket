// SPDX-License-Identifier: Apache-2.0

// Package bkrp implements the BackupKey Remote Protocol (MS-BKRP)
// for retrieving domain backup keys used to decrypt DPAPI secrets.
package bkrp

import (
	"bytes"
	"encoding/binary"
	"fmt"

	"gopacket/pkg/dcerpc"
)

// BKRP Interface UUID: 3dde7c30-165d-11d1-ab8f-00805f14db40
var UUID = [16]byte{
	0x30, 0x7c, 0xde, 0x3d, 0x5d, 0x16, 0xd1, 0x11,
	0xab, 0x8f, 0x00, 0x80, 0x5f, 0x14, 0xdb, 0x40,
}

const (
	MajorVersion = 1
	MinorVersion = 0

	// Operations
	OpBackuprKey = 0
)

// Action GUIDs - these are passed in pguidActionAgent
var (
	// BACKUPKEY_BACKUP_GUID - 7F752B10-178E-11D1-AB8F-00805F14DB40 - backup a secret (ServerWrap)
	BACKUPKEY_BACKUP_GUID = [16]byte{
		0x10, 0x2B, 0x75, 0x7F, 0x8E, 0x17, 0xD1, 0x11,
		0xAB, 0x8F, 0x00, 0x80, 0x5F, 0x14, 0xDB, 0x40,
	}

	// BACKUPKEY_RESTORE_GUID - 47270C64-2FC7-499B-AC5B-0E37CDCE899A - restore a secret (ClientWrap)
	BACKUPKEY_RESTORE_GUID = [16]byte{
		0x64, 0x0C, 0x27, 0x47, 0xC7, 0x2F, 0x9B, 0x49,
		0xAC, 0x5B, 0x0E, 0x37, 0xCD, 0xCE, 0x89, 0x9A,
	}

	// BACKUPKEY_RETRIEVE_BACKUP_KEY_GUID - 018FF48A-EABA-40C6-8F6D-72370240E967 - retrieve domain backup key
	BACKUPKEY_RETRIEVE_BACKUP_KEY_GUID = [16]byte{
		0x8A, 0xF4, 0x8F, 0x01, 0xBA, 0xEA, 0xC6, 0x40,
		0x8F, 0x6D, 0x72, 0x37, 0x02, 0x40, 0xE9, 0x67,
	}

	// BACKUPKEY_RESTORE_GUID_WIN2K - 7FE94D50-178E-11D1-AB8F-00805F14DB40 - legacy restore (ServerWrap)
	BACKUPKEY_RESTORE_GUID_WIN2K = [16]byte{
		0x50, 0x4D, 0xE9, 0x7F, 0x8E, 0x17, 0xD1, 0x11,
		0xAB, 0x8F, 0x00, 0x80, 0x5F, 0x14, 0xDB, 0x40,
	}
)

// Client provides BKRP operations
type Client struct {
	rpc *dcerpc.Client
}

// NewClient creates a new BKRP client
func NewClient(rpc *dcerpc.Client) *Client {
	return &Client{rpc: rpc}
}

// GetBackupKey retrieves the domain backup key from the DC
// This requires Domain Admin or equivalent privileges
func (c *Client) GetBackupKey() ([]byte, error) {
	return c.backuprKey(BACKUPKEY_RETRIEVE_BACKUP_KEY_GUID, nil)
}

// BackupSecret backs up a secret using the domain backup key
func (c *Client) BackupSecret(data []byte) ([]byte, error) {
	return c.backuprKey(BACKUPKEY_BACKUP_GUID, data)
}

// RestoreSecret restores a previously backed up secret
func (c *Client) RestoreSecret(data []byte) ([]byte, error) {
	return c.backuprKey(BACKUPKEY_RESTORE_GUID, data)
}

// backuprKey implements the BackuprKey RPC call
func (c *Client) backuprKey(actionGUID [16]byte, data []byte) ([]byte, error) {
	buf := new(bytes.Buffer)

	// pguidActionAgent: GUID (embedded, 16 bytes)
	// Impacket passes this inline, not as a pointer
	buf.Write(actionGUID[:])

	// pDataIn: byte* (conformant varying array)
	// For NULL: just a NULL pointer (0)
	// For non-NULL: pointer + deferred conformant array
	if data == nil {
		binary.Write(buf, binary.LittleEndian, uint32(0)) // NULL pointer
	} else {
		binary.Write(buf, binary.LittleEndian, uint32(0x00020000)) // Pointer referent ID
	}

	// cbDataIn: DWORD
	binary.Write(buf, binary.LittleEndian, uint32(len(data)))

	// dwParam: DWORD (flags, 0 for backup key retrieval)
	binary.Write(buf, binary.LittleEndian, uint32(0))

	// === Deferred pointer data for pDataIn ===
	if data != nil {
		// Conformant varying array: MaxCount + Offset + ActualCount + data
		binary.Write(buf, binary.LittleEndian, uint32(len(data))) // MaxCount
		binary.Write(buf, binary.LittleEndian, uint32(0))         // Offset
		binary.Write(buf, binary.LittleEndian, uint32(len(data))) // ActualCount
		buf.Write(data)
		// Align to 4 bytes
		if len(data)%4 != 0 {
			buf.Write(make([]byte, 4-len(data)%4))
		}
	}

	// Call with authenticated RPC
	var resp []byte
	var err error
	if c.rpc.Authenticated {
		resp, err = c.rpc.CallAuthAuto(OpBackuprKey, buf.Bytes())
	} else {
		resp, err = c.rpc.Call(OpBackuprKey, buf.Bytes())
	}
	if err != nil {
		return nil, fmt.Errorf("BackuprKey failed: %v", err)
	}

	// Parse response
	// Response structure:
	// ppDataOut: byte** (pointer to pointer)
	// pcbDataOut: DWORD* (pointer to size)
	// Return value: DWORD

	if len(resp) < 16 {
		return nil, fmt.Errorf("response too short: %d bytes", len(resp))
	}

	r := bytes.NewReader(resp)

	// ppDataOut pointer
	var dataOutPtr uint32
	binary.Read(r, binary.LittleEndian, &dataOutPtr)

	// pcbDataOut
	var dataOutLen uint32
	binary.Read(r, binary.LittleEndian, &dataOutLen)

	// Return value
	r.Seek(-4, 2) // Seek to end - 4
	var retVal uint32
	binary.Read(r, binary.LittleEndian, &retVal)

	if retVal != 0 {
		return nil, fmt.Errorf("BackuprKey returned error: 0x%08x", retVal)
	}

	if dataOutPtr == 0 || dataOutLen == 0 {
		return nil, fmt.Errorf("no data returned")
	}

	// Parse the conformant array
	// Skip to after the pointers (8 bytes) to get to deferred data
	r.Seek(8, 0)

	// Conformant array: MaxCount + data
	var maxCount uint32
	binary.Read(r, binary.LittleEndian, &maxCount)

	outData := make([]byte, dataOutLen)
	r.Read(outData)

	return outData, nil
}
