// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jacob Paullus

package svcctl

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"unicode/utf16"

	"gopacket/pkg/dcerpc"
)

// MS-SCMR (Service Control Manager Remote Protocol)
// UUID: 367ABB81-9844-35F1-AD32-98F038001003 v2.0

var UUID = [16]byte{
	0x81, 0xbb, 0x7a, 0x36, 0x44, 0x98, 0xf1, 0x35,
	0xad, 0x32, 0x98, 0xf0, 0x38, 0x00, 0x10, 0x03,
}

const MajorVersion = 2
const MinorVersion = 0

// Operation numbers
const (
	OpRCloseServiceHandle         = 0
	OpRControlService             = 1
	OpRDeleteService              = 2
	OpRLockServiceDatabase        = 3
	OpRQueryServiceObjectSecurity = 4
	OpRSetServiceObjectSecurity   = 5
	OpRQueryServiceStatus         = 6
	OpRSetServiceStatus           = 7
	OpRUnlockServiceDatabase      = 8
	OpRNotifyBootConfigStatus     = 9
	OpRChangeServiceConfigW       = 11
	OpRCreateServiceW             = 12
	OpREnumDependentServicesW     = 13
	OpREnumServicesStatusW        = 14
	OpROpenSCManagerW             = 15
	OpROpenServiceW               = 16
	OpRQueryServiceConfigW        = 17
	OpRQueryServiceLockStatusW    = 18
	OpRStartServiceW              = 19
	OpRGetServiceDisplayNameW     = 20
	OpRGetServiceKeyNameW         = 21
)

// Service access rights
const (
	SERVICE_QUERY_CONFIG         = 0x0001
	SERVICE_CHANGE_CONFIG        = 0x0002
	SERVICE_QUERY_STATUS         = 0x0004
	SERVICE_ENUMERATE_DEPENDENTS = 0x0008
	SERVICE_START                = 0x0010
	SERVICE_STOP                 = 0x0020
	SERVICE_PAUSE_CONTINUE       = 0x0040
	SERVICE_INTERROGATE          = 0x0080
	SERVICE_USER_DEFINED_CONTROL = 0x0100
	SERVICE_ALL_ACCESS           = 0x01FF
	SC_MANAGER_ALL_ACCESS        = 0x000F003F
)

// Service control codes
const (
	SERVICE_CONTROL_STOP        = 0x00000001
	SERVICE_CONTROL_PAUSE       = 0x00000002
	SERVICE_CONTROL_CONTINUE    = 0x00000003
	SERVICE_CONTROL_INTERROGATE = 0x00000004
)

// Service states
const (
	SERVICE_STOPPED          = 0x00000001
	SERVICE_START_PENDING    = 0x00000002
	SERVICE_STOP_PENDING     = 0x00000003
	SERVICE_RUNNING          = 0x00000004
	SERVICE_CONTINUE_PENDING = 0x00000005
	SERVICE_PAUSE_PENDING    = 0x00000006
	SERVICE_PAUSED           = 0x00000007
)

// Enum Service States
const (
	SERVICE_ACTIVE    = 0x00000001
	SERVICE_INACTIVE  = 0x00000002
	SERVICE_STATE_ALL = 0x00000003
)

// Service types
const (
	SERVICE_KERNEL_DRIVER       = 0x00000001
	SERVICE_FILE_SYSTEM_DRIVER  = 0x00000002
	SERVICE_ADAPTER             = 0x00000004
	SERVICE_RECOGNIZER_DRIVER   = 0x00000008
	SERVICE_WIN32_OWN_PROCESS   = 0x00000010
	SERVICE_WIN32_SHARE_PROCESS = 0x00000020
	SERVICE_INTERACTIVE_PROCESS = 0x00000100
)

// Service error control
const (
	ERROR_IGNORE   = 0x00000000
	ERROR_NORMAL   = 0x00000001
	ERROR_SEVERE   = 0x00000002
	ERROR_CRITICAL = 0x00000003
)

// Service start types
const (
	SERVICE_BOOT_START   = 0x00000000
	SERVICE_SYSTEM_START = 0x00000001
	SERVICE_AUTO_START   = 0x00000002
	SERVICE_DEMAND_START = 0x00000003
	SERVICE_DISABLED     = 0x00000004
)

// Error codes
const (
	ERROR_SUCCESS                 = 0
	ERROR_ACCESS_DENIED           = 5
	ERROR_INVALID_HANDLE          = 6
	ERROR_SERVICE_DOES_NOT_EXIST  = 1060
	ERROR_SERVICE_NOT_ACTIVE      = 1062
	ERROR_SERVICE_ALREADY_RUNNING = 1056
	ERROR_SERVICE_EXISTS          = 1073
)

// ServiceStatus represents the status of a service
type ServiceStatus struct {
	ServiceType             uint32
	CurrentState            uint32
	ControlsAccepted        uint32
	Win32ExitCode           uint32
	ServiceSpecificExitCode uint32
	CheckPoint              uint32
	WaitHint                uint32
}

// ServiceController manages service operations
type ServiceController struct {
	client    *dcerpc.Client
	scmHandle []byte
}

// NewServiceController creates a new service controller
func NewServiceController(client *dcerpc.Client) (*ServiceController, error) {
	sc := &ServiceController{client: client}

	// Open SCManager
	handle, err := sc.openSCManager("")
	if err != nil {
		return nil, err
	}
	sc.scmHandle = handle

	return sc, nil
}

// openSCManager opens the Service Control Manager
func (sc *ServiceController) openSCManager(machineName string) ([]byte, error) {
	buf := new(bytes.Buffer)

	// lpMachineName (pointer to string or NULL)
	if machineName == "" {
		binary.Write(buf, binary.LittleEndian, uint32(0)) // NULL
	} else {
		binary.Write(buf, binary.LittleEndian, uint32(0x20000))
		writeWideString(buf, machineName)
	}

	// lpDatabaseName (NULL - default database)
	binary.Write(buf, binary.LittleEndian, uint32(0))

	// dwDesiredAccess
	binary.Write(buf, binary.LittleEndian, uint32(SC_MANAGER_ALL_ACCESS))

	resp, err := sc.client.Call(OpROpenSCManagerW, buf.Bytes())
	if err != nil {
		return nil, err
	}

	if len(resp) < 24 {
		return nil, fmt.Errorf("response too short")
	}

	// Response: lpScHandle (20 bytes) + return value (4 bytes)
	handle := make([]byte, 20)
	copy(handle, resp[:20])

	retVal := binary.LittleEndian.Uint32(resp[20:24])
	if retVal != ERROR_SUCCESS {
		return nil, fmt.Errorf("OpenSCManager failed: 0x%08x", retVal)
	}

	return handle, nil
}

// CreateService creates a new service
func (sc *ServiceController) CreateService(serviceName, displayName, binaryPath string, serviceType, startType, errorControl uint32) ([]byte, error) {
	buf := new(bytes.Buffer)

	// hSCManager (20 bytes)
	buf.Write(sc.scmHandle)

	// lpServiceName
	writeWideString(buf, serviceName)

	// lpDisplayName (pointer + string)
	if displayName == "" {
		displayName = serviceName
	}
	binary.Write(buf, binary.LittleEndian, uint32(0x20000))
	writeWideString(buf, displayName)

	// dwDesiredAccess
	binary.Write(buf, binary.LittleEndian, uint32(SERVICE_ALL_ACCESS))

	// dwServiceType
	binary.Write(buf, binary.LittleEndian, serviceType)

	// dwStartType
	binary.Write(buf, binary.LittleEndian, startType)

	// dwErrorControl
	binary.Write(buf, binary.LittleEndian, errorControl)

	// lpBinaryPathName
	writeWideString(buf, binaryPath)

	// lpLoadOrderGroup (NULL)
	binary.Write(buf, binary.LittleEndian, uint32(0))

	// lpdwTagId (NULL)
	binary.Write(buf, binary.LittleEndian, uint32(0))

	// lpDependencies (NULL)
	binary.Write(buf, binary.LittleEndian, uint32(0))

	// dwDependSize
	binary.Write(buf, binary.LittleEndian, uint32(0))

	// lpServiceStartName (NULL)
	binary.Write(buf, binary.LittleEndian, uint32(0))

	// lpPassword (NULL)
	binary.Write(buf, binary.LittleEndian, uint32(0))

	// dwPwSize
	binary.Write(buf, binary.LittleEndian, uint32(0))

	resp, err := sc.client.Call(OpRCreateServiceW, buf.Bytes())
	if err != nil {
		return nil, err
	}

	if len(resp) < 28 {
		return nil, fmt.Errorf("response too short")
	}

	// Response: lpTagId (4 bytes) + lpServiceHandle (20 bytes) + return value (4 bytes)
	// Actually return value is last 4 bytes.
	// But MS-SCMR says: lpTagId (4), lpServiceHandle (20), ReturnValue (4). Total 28 bytes minimum.

	retVal := binary.LittleEndian.Uint32(resp[len(resp)-4:])
	if retVal != ERROR_SUCCESS {
		return nil, fmt.Errorf("CreateService failed: 0x%08x", retVal)
	}

	// Extract handle (offset 4, length 20)
	handle := make([]byte, 20)
	copy(handle, resp[4:24])

	return handle, nil
}

// DeleteService deletes a service
func (sc *ServiceController) DeleteService(serviceHandle []byte) error {
	buf := new(bytes.Buffer)
	buf.Write(serviceHandle)

	resp, err := sc.client.Call(OpRDeleteService, buf.Bytes())
	if err != nil {
		return err
	}

	if len(resp) < 4 {
		return fmt.Errorf("response too short")
	}

	retVal := binary.LittleEndian.Uint32(resp[:4])
	if retVal != ERROR_SUCCESS {
		return fmt.Errorf("DeleteService failed: 0x%08x", retVal)
	}

	return nil
}

// OpenService opens a service by name
func (sc *ServiceController) OpenService(serviceName string, desiredAccess uint32) ([]byte, error) {
	buf := new(bytes.Buffer)

	// hSCManager (20 bytes)
	buf.Write(sc.scmHandle)

	// lpServiceName
	writeWideString(buf, serviceName)

	// dwDesiredAccess
	binary.Write(buf, binary.LittleEndian, desiredAccess)

	resp, err := sc.client.Call(OpROpenServiceW, buf.Bytes())
	if err != nil {
		return nil, err
	}

	if len(resp) < 24 {
		return nil, fmt.Errorf("response too short")
	}

	handle := make([]byte, 20)
	copy(handle, resp[:20])

	retVal := binary.LittleEndian.Uint32(resp[20:24])
	if retVal != ERROR_SUCCESS {
		return nil, fmt.Errorf("OpenService(%s) failed: 0x%08x", serviceName, retVal)
	}

	return handle, nil
}

// QueryServiceStatus queries the status of a service
func (sc *ServiceController) QueryServiceStatus(serviceHandle []byte) (*ServiceStatus, error) {
	buf := new(bytes.Buffer)
	buf.Write(serviceHandle)

	resp, err := sc.client.Call(OpRQueryServiceStatus, buf.Bytes())
	if err != nil {
		return nil, err
	}

	if len(resp) < 32 {
		return nil, fmt.Errorf("response too short")
	}

	r := bytes.NewReader(resp)
	status := &ServiceStatus{}

	binary.Read(r, binary.LittleEndian, &status.ServiceType)
	binary.Read(r, binary.LittleEndian, &status.CurrentState)
	binary.Read(r, binary.LittleEndian, &status.ControlsAccepted)
	binary.Read(r, binary.LittleEndian, &status.Win32ExitCode)
	binary.Read(r, binary.LittleEndian, &status.ServiceSpecificExitCode)
	binary.Read(r, binary.LittleEndian, &status.CheckPoint)
	binary.Read(r, binary.LittleEndian, &status.WaitHint)

	var retVal uint32
	binary.Read(r, binary.LittleEndian, &retVal)

	if retVal != ERROR_SUCCESS {
		return nil, fmt.Errorf("QueryServiceStatus failed: 0x%08x", retVal)
	}

	return status, nil
}

// StartService starts a service
func (sc *ServiceController) StartService(serviceHandle []byte) error {
	buf := new(bytes.Buffer)
	buf.Write(serviceHandle)

	// argc (number of arguments)
	binary.Write(buf, binary.LittleEndian, uint32(0))

	// argv (NULL - no arguments)
	binary.Write(buf, binary.LittleEndian, uint32(0))

	resp, err := sc.client.Call(OpRStartServiceW, buf.Bytes())
	if err != nil {
		return err
	}

	if len(resp) < 4 {
		return fmt.Errorf("response too short")
	}

	retVal := binary.LittleEndian.Uint32(resp[:4])
	if retVal != ERROR_SUCCESS && retVal != ERROR_SERVICE_ALREADY_RUNNING {
		return fmt.Errorf("StartService failed: 0x%08x", retVal)
	}

	return nil
}

// StopService stops a service
func (sc *ServiceController) StopService(serviceHandle []byte) (*ServiceStatus, error) {
	buf := new(bytes.Buffer)
	buf.Write(serviceHandle)

	// dwControl
	binary.Write(buf, binary.LittleEndian, uint32(SERVICE_CONTROL_STOP))

	resp, err := sc.client.Call(OpRControlService, buf.Bytes())
	if err != nil {
		return nil, err
	}

	if len(resp) < 32 {
		return nil, fmt.Errorf("response too short")
	}

	r := bytes.NewReader(resp)
	status := &ServiceStatus{}

	binary.Read(r, binary.LittleEndian, &status.ServiceType)
	binary.Read(r, binary.LittleEndian, &status.CurrentState)
	binary.Read(r, binary.LittleEndian, &status.ControlsAccepted)
	binary.Read(r, binary.LittleEndian, &status.Win32ExitCode)
	binary.Read(r, binary.LittleEndian, &status.ServiceSpecificExitCode)
	binary.Read(r, binary.LittleEndian, &status.CheckPoint)
	binary.Read(r, binary.LittleEndian, &status.WaitHint)

	var retVal uint32
	binary.Read(r, binary.LittleEndian, &retVal)

	if retVal != ERROR_SUCCESS && retVal != ERROR_SERVICE_NOT_ACTIVE {
		return nil, fmt.Errorf("StopService failed: 0x%08x", retVal)
	}

	return status, nil
}

// ServiceConfig represents the configuration of a service
type ServiceConfig struct {
	ServiceType      uint32
	StartType        uint32
	ErrorControl     uint32
	BinaryPathName   string
	LoadOrderGroup   string
	TagId            uint32
	Dependencies     string
	ServiceStartName string
	DisplayName      string
}

// QueryServiceConfig queries the configuration of a service
func (sc *ServiceController) QueryServiceConfig(serviceHandle []byte) (*ServiceConfig, error) {
	buf := new(bytes.Buffer)
	buf.Write(serviceHandle)

	// cbBufSize - start with 0 to get required size
	binary.Write(buf, binary.LittleEndian, uint32(0))

	resp, err := sc.client.Call(OpRQueryServiceConfigW, buf.Bytes())
	if err != nil {
		return nil, err
	}

	if len(resp) < 8 {
		return nil, fmt.Errorf("response too short")
	}

	// Get required buffer size from the response
	bytesNeeded := binary.LittleEndian.Uint32(resp[len(resp)-8 : len(resp)-4])

	// Now call again with proper buffer size
	buf = new(bytes.Buffer)
	buf.Write(serviceHandle)
	binary.Write(buf, binary.LittleEndian, bytesNeeded)

	resp, err = sc.client.Call(OpRQueryServiceConfigW, buf.Bytes())
	if err != nil {
		return nil, err
	}

	if len(resp) < 36 {
		return nil, fmt.Errorf("response too short for config")
	}

	config := &ServiceConfig{}

	// Fixed fields (NDR structure):
	// [0:4]   dwServiceType
	// [4:8]   dwStartType
	// [8:12]  dwErrorControl
	// [12:16] lpBinaryPathName (pointer referent ID)
	// [16:20] lpLoadOrderGroup (pointer referent ID)
	// [20:24] dwTagId
	// [24:28] lpDependencies (pointer referent ID)
	// [28:32] dwDependSize
	// [32:36] lpServiceStartName (pointer referent ID)
	// [36:40] lpDisplayName (pointer referent ID)
	// QUERY_SERVICE_CONFIGW fixed part (36 bytes):
	// [0:4]   dwServiceType
	// [4:8]   dwStartType
	// [8:12]  dwErrorControl
	// [12:16] lpBinaryPathName ptr
	// [16:20] lpLoadOrderGroup ptr
	// [20:24] dwTagId
	// [24:28] lpDependencies ptr
	// [28:32] lpServiceStartName ptr
	// [32:36] lpDisplayName ptr
	config.ServiceType = binary.LittleEndian.Uint32(resp[0:4])
	config.StartType = binary.LittleEndian.Uint32(resp[4:8])
	config.ErrorControl = binary.LittleEndian.Uint32(resp[8:12])

	ptrBinaryPath := binary.LittleEndian.Uint32(resp[12:16])
	ptrLoadOrderGroup := binary.LittleEndian.Uint32(resp[16:20])
	config.TagId = binary.LittleEndian.Uint32(resp[20:24])
	ptrDependencies := binary.LittleEndian.Uint32(resp[24:28])
	ptrServiceStartName := binary.LittleEndian.Uint32(resp[28:32])
	ptrDisplayName := binary.LittleEndian.Uint32(resp[32:36])

	// Deferred string data follows the fixed part at offset 36
	offset := 36

	// Read deferred NDR conformant varying strings in pointer declaration order
	if ptrBinaryPath != 0 {
		config.BinaryPathName, offset = readNDRString(resp, offset)
	}
	if ptrLoadOrderGroup != 0 {
		config.LoadOrderGroup, offset = readNDRString(resp, offset)
	}
	if ptrDependencies != 0 {
		config.Dependencies, offset = readNDRString(resp, offset)
	}
	if ptrServiceStartName != 0 {
		config.ServiceStartName, offset = readNDRString(resp, offset)
	}
	if ptrDisplayName != 0 {
		config.DisplayName, offset = readNDRString(resp, offset)
	}

	// Last 8 bytes: pcbBytesNeeded (4) + ReturnValue (4)
	if len(resp) >= 4 {
		retVal := binary.LittleEndian.Uint32(resp[len(resp)-4:])
		if retVal != ERROR_SUCCESS {
			return nil, fmt.Errorf("QueryServiceConfigW failed: 0x%08x", retVal)
		}
	}

	return config, nil
}

// readNDRString reads a conformant varying NDR string from resp at offset.
// Returns the decoded string and the new offset after the string data.
func readNDRString(resp []byte, offset int) (string, int) {
	if offset+12 > len(resp) {
		return "", offset
	}
	maxCount := binary.LittleEndian.Uint32(resp[offset : offset+4])
	// actualOffset := binary.LittleEndian.Uint32(resp[offset+4 : offset+8])
	actualCount := binary.LittleEndian.Uint32(resp[offset+8 : offset+12])
	offset += 12

	_ = maxCount

	byteLen := int(actualCount) * 2
	if offset+byteLen > len(resp) {
		return "", offset
	}

	s := utf16Decode(resp[offset : offset+byteLen])
	offset += byteLen

	// Pad to 4-byte boundary
	if offset%4 != 0 {
		offset += 4 - (offset % 4)
	}
	return s, offset
}

// SERVICE_NO_CHANGE is used for uint32 params that shouldn't change
const SERVICE_NO_CHANGE = 0xFFFFFFFF

// ChangeServiceConfigParams holds parameters for ChangeServiceConfig
type ChangeServiceConfigParams struct {
	ServiceType      uint32 // 0xFFFFFFFF = no change
	StartType        uint32 // 0xFFFFFFFF = no change
	ErrorControl     uint32 // 0xFFFFFFFF = no change
	BinaryPathName   string // "" = no change
	LoadOrderGroup   string // "" = no change
	Dependencies     string // "" = no change
	ServiceStartName string // "" = no change
	Password         string // "" = no change
	DisplayName      string // "" = no change
}

// ChangeServiceConfig changes the configuration of a service
func (sc *ServiceController) ChangeServiceConfig(serviceHandle []byte, params *ChangeServiceConfigParams) error {
	buf := new(bytes.Buffer)
	buf.Write(serviceHandle)

	binary.Write(buf, binary.LittleEndian, params.ServiceType)
	binary.Write(buf, binary.LittleEndian, params.StartType)
	binary.Write(buf, binary.LittleEndian, params.ErrorControl)

	// lpBinaryPathName
	writeOptionalString(buf, params.BinaryPathName)

	// lpLoadOrderGroup
	writeOptionalString(buf, params.LoadOrderGroup)

	// lpdwTagId - NULL
	binary.Write(buf, binary.LittleEndian, uint32(0))

	// lpDependencies - NULL (not commonly changed via CLI)
	binary.Write(buf, binary.LittleEndian, uint32(0))
	// dwDependSize
	binary.Write(buf, binary.LittleEndian, uint32(0))

	// lpServiceStartName
	writeOptionalString(buf, params.ServiceStartName)

	// lpPassword
	if params.Password != "" {
		pwBytes := encodeUTF16LE(params.Password)
		binary.Write(buf, binary.LittleEndian, uint32(0x20000)) // pointer
		buf.Write(pwBytes)
		// Pad to 4-byte boundary
		if buf.Len()%4 != 0 {
			buf.Write(make([]byte, 4-(buf.Len()%4)))
		}
		binary.Write(buf, binary.LittleEndian, uint32(len(pwBytes)))
	} else {
		binary.Write(buf, binary.LittleEndian, uint32(0)) // NULL
		binary.Write(buf, binary.LittleEndian, uint32(0)) // dwPwSize
	}

	// lpDisplayName
	writeOptionalString(buf, params.DisplayName)

	resp, err := sc.client.Call(OpRChangeServiceConfigW, buf.Bytes())
	if err != nil {
		return err
	}

	if len(resp) < 8 {
		return fmt.Errorf("response too short")
	}

	retVal := binary.LittleEndian.Uint32(resp[len(resp)-4:])
	if retVal != ERROR_SUCCESS {
		return fmt.Errorf("ChangeServiceConfig failed: 0x%08x", retVal)
	}

	return nil
}

// writeOptionalString writes a pointer + NDR string if non-empty, or NULL pointer
func writeOptionalString(buf *bytes.Buffer, s string) {
	if s == "" {
		binary.Write(buf, binary.LittleEndian, uint32(0)) // NULL pointer
	} else {
		binary.Write(buf, binary.LittleEndian, uint32(0x20000)) // pointer referent ID
		writeWideString(buf, s)
	}
}

// encodeUTF16LE encodes a string as UTF-16LE bytes with null terminator
func encodeUTF16LE(s string) []byte {
	u16 := utf16.Encode([]rune(s))
	u16 = append(u16, 0)
	b := make([]byte, len(u16)*2)
	for i, c := range u16 {
		binary.LittleEndian.PutUint16(b[i*2:], c)
	}
	return b
}

// EnumServiceEntry represents a service returned by EnumServicesStatus
type EnumServiceEntry struct {
	ServiceName string
	DisplayName string
	Status      ServiceStatus
}

// EnumServicesStatus lists services with full details
func (sc *ServiceController) EnumServicesStatus(serviceType, serviceState uint32) ([]EnumServiceEntry, error) {
	// First call with small buffer to probe the required size,
	// then retry with the exact needed buffer size
	bufSize := uint32(1024)

	for {
		buf := new(bytes.Buffer)
		buf.Write(sc.scmHandle)
		binary.Write(buf, binary.LittleEndian, serviceType)
		binary.Write(buf, binary.LittleEndian, serviceState)
		binary.Write(buf, binary.LittleEndian, bufSize)

		// lpResumeHandle [in, out, unique]
		binary.Write(buf, binary.LittleEndian, uint32(1)) // Pointer referent ID
		binary.Write(buf, binary.LittleEndian, uint32(0)) // Always start from 0

		resp, err := sc.client.Call(OpREnumServicesStatusW, buf.Bytes())
		if err != nil {
			return nil, err
		}

		// Response layout (NDR):
		// [0:4]              MaxCount of conformant byte array
		// [4:4+MaxCount]     Byte array data (ENUM_SERVICE_STATUSW entries + strings)
		// [4+MaxCount:...]   pcbBytesNeeded(4) + lpServicesReturned(4)
		//                    + lpResumeHandle ptr(4) + value(4) + ReturnValue(4)
		if len(resp) < 24 {
			return nil, fmt.Errorf("response too short (len=%d)", len(resp))
		}

		maxCount := binary.LittleEndian.Uint32(resp[0:4])
		arrayEnd := 4 + int(maxCount)

		// Trailer fields follow the byte array
		trailerOff := arrayEnd
		if trailerOff+12 > len(resp) {
			return nil, fmt.Errorf("response too short for trailer (len=%d, arrayEnd=%d)", len(resp), arrayEnd)
		}

		bytesNeeded := binary.LittleEndian.Uint32(resp[trailerOff : trailerOff+4])
		servicesReturned := binary.LittleEndian.Uint32(resp[trailerOff+4 : trailerOff+8])
		resumePtr := binary.LittleEndian.Uint32(resp[trailerOff+8 : trailerOff+12])
		off := trailerOff + 12
		if resumePtr != 0 {
			off += 4 // skip resume handle value
		}
		retVal := uint32(0)
		if off+4 <= len(resp) {
			retVal = binary.LittleEndian.Uint32(resp[off : off+4])
		}

		// ERROR_MORE_DATA = 234 - need bigger buffer, retry from scratch
		if retVal == 234 {
			if bytesNeeded == 0 {
				bytesNeeded = 64 * 1024
			}
			bufSize = bytesNeeded
			continue
		}

		if retVal != ERROR_SUCCESS {
			return nil, fmt.Errorf("EnumServicesStatusW failed: 0x%08x", retVal)
		}

		entries := make([]EnumServiceEntry, 0, servicesReturned)
		if servicesReturned == 0 {
			return entries, nil
		}

		// The byte array (offset 4 to arrayEnd) contains ENUM_SERVICE_STATUSW structures:
		// Each entry is 36 bytes:
		//   ServiceName offset (4) + DisplayName offset (4) + SERVICE_STATUS (28)
		// String data (UTF-16LE) follows the fixed entries, referenced by offsets
		// relative to the start of the byte array
		bufStart := 4 // start of the byte array data

		for i := uint32(0); i < servicesReturned; i++ {
			entryOff := bufStart + int(i)*36
			if entryOff+36 > arrayEnd {
				break
			}

			nameOff := binary.LittleEndian.Uint32(resp[entryOff : entryOff+4])
			dispOff := binary.LittleEndian.Uint32(resp[entryOff+4 : entryOff+8])

			var status ServiceStatus
			status.ServiceType = binary.LittleEndian.Uint32(resp[entryOff+8 : entryOff+12])
			status.CurrentState = binary.LittleEndian.Uint32(resp[entryOff+12 : entryOff+16])
			status.ControlsAccepted = binary.LittleEndian.Uint32(resp[entryOff+16 : entryOff+20])
			status.Win32ExitCode = binary.LittleEndian.Uint32(resp[entryOff+20 : entryOff+24])
			status.ServiceSpecificExitCode = binary.LittleEndian.Uint32(resp[entryOff+24 : entryOff+28])
			status.CheckPoint = binary.LittleEndian.Uint32(resp[entryOff+28 : entryOff+32])
			status.WaitHint = binary.LittleEndian.Uint32(resp[entryOff+32 : entryOff+36])

			entry := EnumServiceEntry{Status: status}

			if nameOff != 0 {
				absOff := bufStart + int(nameOff)
				if absOff >= bufStart && absOff < arrayEnd {
					entry.ServiceName = utf16DecodeFromOffset(resp, absOff)
				}
			}
			if dispOff != 0 {
				absOff := bufStart + int(dispOff)
				if absOff >= bufStart && absOff < arrayEnd {
					entry.DisplayName = utf16DecodeFromOffset(resp, absOff)
				}
			}

			entries = append(entries, entry)
		}

		return entries, nil
	}
}

func utf16DecodeFromOffset(b []byte, offset int) string {
	// Scan for null terminator
	end := offset
	for end+1 < len(b) {
		if b[end] == 0 && b[end+1] == 0 {
			break
		}
		end += 2
	}
	return utf16Decode(b[offset:end])
}

func utf16Decode(b []byte) string {
	u16s := make([]uint16, len(b)/2)
	for i := range u16s {
		u16s[i] = binary.LittleEndian.Uint16(b[i*2 : i*2+2])
	}
	// Trim null
	if len(u16s) > 0 && u16s[len(u16s)-1] == 0 {
		u16s = u16s[:len(u16s)-1]
	}
	return string(utf16.Decode(u16s))
}

// CloseServiceHandle closes a service handle
func (sc *ServiceController) CloseServiceHandle(handle []byte) error {
	buf := new(bytes.Buffer)
	buf.Write(handle)

	_, err := sc.client.Call(OpRCloseServiceHandle, buf.Bytes())
	if err != nil {
		return err
	}

	return nil
}

// Close closes the SCManager handle
func (sc *ServiceController) Close() {
	if sc.scmHandle != nil {
		sc.CloseServiceHandle(sc.scmHandle)
		sc.scmHandle = nil
	}
}

// writeWideString writes a UTF-16LE string with NDR format
func writeWideString(buf *bytes.Buffer, s string) {
	utf16Chars := utf16.Encode([]rune(s))
	utf16Chars = append(utf16Chars, 0) // null terminator
	charCount := uint32(len(utf16Chars))

	// Conformant varying string
	binary.Write(buf, binary.LittleEndian, charCount) // MaxCount
	binary.Write(buf, binary.LittleEndian, uint32(0)) // Offset
	binary.Write(buf, binary.LittleEndian, charCount) // ActualCount

	for _, c := range utf16Chars {
		binary.Write(buf, binary.LittleEndian, c)
	}

	// Pad to 4-byte boundary
	if buf.Len()%4 != 0 {
		padding := 4 - (buf.Len() % 4)
		buf.Write(make([]byte, padding))
	}
}

// GetServiceState returns a string description of the service state (uppercase, matching Impacket)
func GetServiceState(state uint32) string {
	switch state {
	case SERVICE_STOPPED:
		return "STOPPED"
	case SERVICE_START_PENDING:
		return "START PENDING"
	case SERVICE_STOP_PENDING:
		return "STOP PENDING"
	case SERVICE_RUNNING:
		return "RUNNING"
	case SERVICE_CONTINUE_PENDING:
		return "CONTINUE PENDING"
	case SERVICE_PAUSE_PENDING:
		return "PAUSE PENDING"
	case SERVICE_PAUSED:
		return "PAUSED"
	default:
		return "UNKNOWN"
	}
}
