// SPDX-License-Identifier: Apache-2.0

package smb

import (
	"fmt"
	"os"

	"gopacket/pkg/thirdparty/smb2"
)

// PipeAccess specifies the access mode for named pipes
type PipeAccess int

const (
	PipeAccessReadWrite PipeAccess = iota // Read and write (default)
	PipeAccessRead                        // Read only (for stdout/stderr)
	PipeAccessWrite                       // Write only (for stdin)
)

// OpenPipe opens a named pipe on the IPC$ share with read/write access.
func (c *Client) OpenPipe(name string) (*smb2.File, error) {
	return c.OpenPipeWithAccess(name, PipeAccessReadWrite)
}

// OpenPipeWithAccess opens a named pipe with specified access mode.
func (c *Client) OpenPipeWithAccess(name string, access PipeAccess) (*smb2.File, error) {
	if c.Session == nil {
		return nil, fmt.Errorf("session not established")
	}

	// Ensure we have a handle to IPC$
	if c.ipcShare == nil {
		share, err := c.Session.Mount("IPC$")
		if err != nil {
			return nil, fmt.Errorf("failed to mount IPC$: %v", err)
		}
		c.ipcShare = share
	}

	// Map access mode to os flags
	var flag int
	switch access {
	case PipeAccessRead:
		flag = os.O_RDONLY
	case PipeAccessWrite:
		flag = os.O_WRONLY
	default:
		flag = os.O_RDWR
	}

	f, err := c.ipcShare.OpenFile(name, flag, 0666)
	if err != nil {
		return nil, err
	}
	return f, nil
}
