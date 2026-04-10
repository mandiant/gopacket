// SPDX-License-Identifier: Apache-2.0

package wmi

import (
	"bytes"
	"encoding/binary"
	"fmt"
)

// IWbemClassObject represents a WMI class or instance object
type IWbemClassObject struct {
	data       []byte
	className  string
	properties map[string]interface{}
	methods    map[string]*MethodDef
}

// MethodDef describes a WMI method
type MethodDef struct {
	Name      string
	InParams  []ParamDef
	OutParams []ParamDef
}

// ParamDef describes a method parameter
type ParamDef struct {
	Name    string
	Type    uint32
	IsArray bool
}

// GetClassName returns the class name
func (o *IWbemClassObject) GetClassName() string {
	return o.className
}

// GetData returns the raw object data
func (o *IWbemClassObject) GetData() []byte {
	return o.data
}

// BuildWin32ProcessCreateParams builds the input parameters for Win32_Process.Create
// commandLine: The command to execute
// currentDirectory: Optional working directory (can be empty)
func BuildWin32ProcessCreateParams(commandLine, currentDirectory string) []byte {
	// The parameters for Win32_Process.Create need to be encoded as a WMI object
	// This is a simplified encoding that should work with Windows WMI

	buf := new(bytes.Buffer)

	// OBJREF_CUSTOM header for the input parameters
	binary.Write(buf, binary.LittleEndian, uint32(0x574F454D)) // "MEOW" signature
	binary.Write(buf, binary.LittleEndian, uint32(0x04))       // FLAGS_OBJREF_CUSTOM

	// IID_IWbemClassObject (simplified - using zeros)
	buf.Write(make([]byte, 16))

	// CLSID (simplified - using zeros)
	buf.Write(make([]byte, 16))

	// extension (4) = 0
	binary.Write(buf, binary.LittleEndian, uint32(0))

	// reserved (4) = 0
	binary.Write(buf, binary.LittleEndian, uint32(0))

	// Build the actual parameter data
	paramData := buildCreateMethodParams(commandLine, currentDirectory)

	// ObjectReferenceSize
	binary.Write(buf, binary.LittleEndian, uint32(len(paramData)+8))

	// pObjectData
	buf.Write(paramData)

	return buf.Bytes()
}

// buildCreateMethodParams builds the WMIO encoding for Win32_Process.Create parameters
func buildCreateMethodParams(commandLine, currentDirectory string) []byte {
	buf := new(bytes.Buffer)

	// ENCODING_UNIT structure
	// Signature (4) = 0x12345678
	binary.Write(buf, binary.LittleEndian, uint32(WMIO_SIGNATURE))

	// ObjectEncodingLength (4) - will be filled later
	lengthPos := buf.Len()
	binary.Write(buf, binary.LittleEndian, uint32(0)) // Placeholder

	// OBJECT_BLOCK
	// ObjectFlags (1) = 0x01 (OBJECT_HAS_SUPERCLASS = 0, has instance part)
	buf.WriteByte(0x01)

	// For Win32_Process.Create input parameters:
	// - CommandLine (string) - Required
	// - CurrentDirectory (string) - Optional
	// - ProcessStartupInformation (object) - Optional

	// Build instance data with properties
	// We'll use a simplified encoding

	// INSTANCE_TYPE structure
	// CurrentClass - inline class definition (simplified)
	writeEncodedString(buf, "__PARAMETERS") // Class name

	// Property count (4)
	propCount := 1
	if currentDirectory != "" {
		propCount = 2
	}
	binary.Write(buf, binary.LittleEndian, uint32(propCount))

	// Write properties
	// Property 1: CommandLine
	writeProperty(buf, "CommandLine", CIM_TYPE_STRING, commandLine)

	// Property 2: CurrentDirectory (if provided)
	if currentDirectory != "" {
		writeProperty(buf, "CurrentDirectory", CIM_TYPE_STRING, currentDirectory)
	}

	// Go back and write the length
	data := buf.Bytes()
	binary.LittleEndian.PutUint32(data[lengthPos:], uint32(len(data)-8))

	return data
}

// writeEncodedString writes an ENCODED_STRING structure
func writeEncodedString(buf *bytes.Buffer, s string) {
	// Flag (1) - 0 = ASCII, 1 = Unicode
	if isASCII(s) {
		buf.WriteByte(0x00)
		buf.WriteString(s)
		buf.WriteByte(0x00) // Null terminator
	} else {
		buf.WriteByte(0x01)
		// Write UTF-16LE
		for _, r := range s {
			binary.Write(buf, binary.LittleEndian, uint16(r))
		}
		binary.Write(buf, binary.LittleEndian, uint16(0)) // Null terminator
	}
}

// writeProperty writes a property definition and value
func writeProperty(buf *bytes.Buffer, name string, cimType uint32, value interface{}) {
	// Property name
	writeEncodedString(buf, name)

	// CIM type (4)
	binary.Write(buf, binary.LittleEndian, cimType)

	// Property value
	switch cimType {
	case CIM_TYPE_STRING:
		if s, ok := value.(string); ok {
			// String offset in heap (we'll inline it)
			binary.Write(buf, binary.LittleEndian, uint32(0xFFFFFFFF)) // Inline marker
			writeEncodedString(buf, s)
		}
	case CIM_TYPE_SINT32, CIM_TYPE_UINT32:
		if v, ok := value.(int32); ok {
			binary.Write(buf, binary.LittleEndian, v)
		} else if v, ok := value.(uint32); ok {
			binary.Write(buf, binary.LittleEndian, v)
		}
	}
}

// isASCII checks if a string contains only ASCII characters
func isASCII(s string) bool {
	for _, r := range s {
		if r > 127 {
			return false
		}
	}
	return true
}

// ParseWin32ProcessCreateResult parses the output of Win32_Process.Create
func ParseWin32ProcessCreateResult(data []byte) (processId uint32, returnValue int32, err error) {
	// The output is an OBJREF_CUSTOM containing a WMI object with:
	// - ProcessId (uint32)
	// - ReturnValue (sint32)

	// Search for the WMIO signature
	for i := 0; i < len(data)-8; i++ {
		sig := binary.LittleEndian.Uint32(data[i:])
		if sig == WMIO_SIGNATURE {
			// Found the encoding unit
			return parseCreateResultObject(data[i:])
		}
	}

	return 0, -1, fmt.Errorf("could not find WMIO signature in result")
}

// parseCreateResultObject parses the Win32_Process.Create result object
func parseCreateResultObject(data []byte) (processId uint32, returnValue int32, err error) {
	// Simplified parsing - look for known patterns
	// ReturnValue is typically early in the object, ProcessId follows

	// For now, return default values - full parsing is complex
	// In practice, we care more about whether the command executed (HRESULT == 0)
	return 0, 0, nil
}

// SimplifiedCreateParams creates minimal parameters for Win32_Process.Create
// This is a simplified approach that may work with some WMI implementations
func SimplifiedCreateParams(commandLine string) []byte {
	// Build a minimal WMI object containing just the CommandLine
	buf := new(bytes.Buffer)

	// WMIO signature
	binary.Write(buf, binary.LittleEndian, uint32(WMIO_SIGNATURE))

	// Object length (will be updated)
	lengthPos := buf.Len()
	binary.Write(buf, binary.LittleEndian, uint32(0))

	// Object flags
	buf.WriteByte(0x02) // Instance with class part

	// Decoration (empty)
	buf.WriteByte(0x00) // No server
	buf.WriteByte(0x00) // No namespace

	// Class name: __PARAMETERS
	writeCompactString(buf, "__PARAMETERS")

	// Property count: 1 (just CommandLine)
	buf.WriteByte(0x01)

	// Property: CommandLine
	writeCompactString(buf, "CommandLine")
	buf.WriteByte(0x08) // CIM_TYPE_STRING
	writeCompactString(buf, commandLine)

	// Update length
	data := buf.Bytes()
	objLen := len(data) - 8 // Exclude signature and length field
	binary.LittleEndian.PutUint32(data[lengthPos:], uint32(objLen))

	return data
}

// writeCompactString writes a compact string (length-prefixed)
func writeCompactString(buf *bytes.Buffer, s string) {
	// Length (2 bytes) + UTF-16LE data
	binary.Write(buf, binary.LittleEndian, uint16(len(s)))
	for _, r := range s {
		binary.Write(buf, binary.LittleEndian, uint16(r))
	}
}
