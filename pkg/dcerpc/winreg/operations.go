package winreg

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"unicode/utf16"

	"gopacket/pkg/dcerpc"
)

// KeyInfo contains information about a registry key
type KeyInfo struct {
	ClassName     string
	SubKeys       uint32
	MaxSubKeyLen  uint32
	MaxClassLen   uint32
	Values        uint32
	MaxValueNameLen uint32
	MaxValueDataLen uint32
	LastWriteTime uint64
}

// OpenLocalMachine opens the HKEY_LOCAL_MACHINE root key
func OpenLocalMachine(client *dcerpc.Client, samDesired uint32) ([]byte, error) {
	buf := new(bytes.Buffer)

	// ServerName (PREGISTRY_SERVER_NAME) - NULL pointer
	binary.Write(buf, binary.LittleEndian, uint32(0))

	// samDesired (REGSAM)
	binary.Write(buf, binary.LittleEndian, samDesired)

	resp, err := client.Call(OpOpenLocalMachine, buf.Bytes())
	if err != nil {
		return nil, err
	}

	// Response: phKey (RPC_HKEY - 20 bytes) + error_status_t (4 bytes)
	if len(resp) < 24 {
		return nil, fmt.Errorf("response too short: %d bytes", len(resp))
	}

	handle := make([]byte, 20)
	copy(handle, resp[:20])
	status := binary.LittleEndian.Uint32(resp[20:24])
	if status != ERROR_SUCCESS {
		return nil, fmt.Errorf("OpenLocalMachine failed: 0x%08x", status)
	}

	return handle, nil
}

// OpenUsers opens the HKEY_USERS root key
func OpenUsers(client *dcerpc.Client, samDesired uint32) ([]byte, error) {
	buf := new(bytes.Buffer)

	// ServerName - NULL
	binary.Write(buf, binary.LittleEndian, uint32(0))

	// samDesired
	binary.Write(buf, binary.LittleEndian, samDesired)

	resp, err := client.Call(OpOpenUsers, buf.Bytes())
	if err != nil {
		return nil, err
	}

	if len(resp) < 24 {
		return nil, fmt.Errorf("response too short: %d bytes", len(resp))
	}

	handle := make([]byte, 20)
	copy(handle, resp[:20])
	status := binary.LittleEndian.Uint32(resp[20:24])
	if status != ERROR_SUCCESS {
		return nil, fmt.Errorf("OpenUsers failed: 0x%08x", status)
	}

	return handle, nil
}

// BaseRegOpenKey opens a subkey
func BaseRegOpenKey(client *dcerpc.Client, hKey []byte, subKey string, options, samDesired uint32) ([]byte, error) {
	buf := new(bytes.Buffer)

	// hKey (RPC_HKEY - 20 bytes)
	buf.Write(hKey)

	// lpSubKey (RRP_UNICODE_STRING)
	writeRRPUnicodeString(buf, subKey)

	// dwOptions
	binary.Write(buf, binary.LittleEndian, options)

	// samDesired
	binary.Write(buf, binary.LittleEndian, samDesired)

	resp, err := client.Call(OpBaseRegOpenKey, buf.Bytes())
	if err != nil {
		return nil, err
	}

	if len(resp) < 24 {
		return nil, fmt.Errorf("response too short: %d bytes", len(resp))
	}

	handle := make([]byte, 20)
	copy(handle, resp[:20])
	status := binary.LittleEndian.Uint32(resp[20:24])
	if status != ERROR_SUCCESS {
		return nil, fmt.Errorf("BaseRegOpenKey(%s) failed: 0x%08x", subKey, status)
	}

	return handle, nil
}

// BaseRegCloseKey closes a registry key handle
func BaseRegCloseKey(client *dcerpc.Client, hKey []byte) error {
	buf := new(bytes.Buffer)
	buf.Write(hKey)

	resp, err := client.Call(OpBaseRegCloseKey, buf.Bytes())
	if err != nil {
		return err
	}

	if len(resp) < 24 {
		return fmt.Errorf("response too short")
	}

	// Response: updated handle (20 bytes) + status (4 bytes)
	status := binary.LittleEndian.Uint32(resp[20:24])
	if status != ERROR_SUCCESS {
		return fmt.Errorf("BaseRegCloseKey failed: 0x%08x", status)
	}

	return nil
}

// BaseRegQueryInfoKey retrieves information about a registry key
func BaseRegQueryInfoKey(client *dcerpc.Client, hKey []byte) (*KeyInfo, error) {
	buf := new(bytes.Buffer)

	// hKey
	buf.Write(hKey)

	// lpClassIn (RRP_UNICODE_STRING) - provide empty buffer for class name
	// We need to provide space for the class name to be returned
	// MaxLen = 65534 (max class name), Len = 0, pointer to conformant array
	binary.Write(buf, binary.LittleEndian, uint16(0))      // Length
	binary.Write(buf, binary.LittleEndian, uint16(65534))  // MaximumLength
	binary.Write(buf, binary.LittleEndian, uint32(0x20000)) // Pointer

	// Deferred: conformant array for class name buffer
	binary.Write(buf, binary.LittleEndian, uint32(65534/2)) // MaxCount (chars)
	binary.Write(buf, binary.LittleEndian, uint32(0))       // Offset
	binary.Write(buf, binary.LittleEndian, uint32(0))       // ActualCount

	resp, err := client.Call(OpBaseRegQueryInfoKey, buf.Bytes())
	if err != nil {
		return nil, err
	}

	r := bytes.NewReader(resp)
	info := &KeyInfo{}

	// Parse lpClassOut (RRP_UNICODE_STRING)
	// Structure: Length (2), MaxLength (2), Buffer pointer (4)
	var classLen, classMaxLen uint16
	var classPtr uint32
	binary.Read(r, binary.LittleEndian, &classLen)
	binary.Read(r, binary.LittleEndian, &classMaxLen)
	binary.Read(r, binary.LittleEndian, &classPtr)

	// IMPORTANT: For embedded structures with pointers, the deferred data
	// comes IMMEDIATELY after the structure, before other fields.
	// Read deferred class name data now if pointer was non-null
	if classPtr != 0 {
		var maxCount, offset, actualCount uint32
		binary.Read(r, binary.LittleEndian, &maxCount)
		binary.Read(r, binary.LittleEndian, &offset)
		binary.Read(r, binary.LittleEndian, &actualCount)

		if actualCount > 0 {
			chars := make([]uint16, actualCount)
			binary.Read(r, binary.LittleEndian, &chars)
			// Trim null terminator
			if len(chars) > 0 && chars[len(chars)-1] == 0 {
				chars = chars[:len(chars)-1]
			}
			info.ClassName = string(utf16.Decode(chars))

			// Align to 4-byte boundary after UTF-16 data
			dataBytes := int(actualCount) * 2
			if dataBytes%4 != 0 {
				padding := 4 - (dataBytes % 4)
				r.Seek(int64(padding), 1)
			}
		}
	}

	// Now read fixed output fields
	var subKeys, maxSubKeyLen, maxClassLen, values uint32
	var maxValueNameLen, maxValueDataLen, securityDescLen uint32
	var lastWriteTime uint64

	binary.Read(r, binary.LittleEndian, &subKeys)
	binary.Read(r, binary.LittleEndian, &maxSubKeyLen)
	binary.Read(r, binary.LittleEndian, &maxClassLen)
	binary.Read(r, binary.LittleEndian, &values)
	binary.Read(r, binary.LittleEndian, &maxValueNameLen)
	binary.Read(r, binary.LittleEndian, &maxValueDataLen)
	binary.Read(r, binary.LittleEndian, &securityDescLen)
	binary.Read(r, binary.LittleEndian, &lastWriteTime)

	info.SubKeys = subKeys
	info.MaxSubKeyLen = maxSubKeyLen
	info.MaxClassLen = maxClassLen
	info.Values = values
	info.MaxValueNameLen = maxValueNameLen
	info.MaxValueDataLen = maxValueDataLen
	info.LastWriteTime = lastWriteTime

	// Read return status (last 4 bytes)
	r.Seek(-4, 2)
	var status uint32
	binary.Read(r, binary.LittleEndian, &status)
	if status != ERROR_SUCCESS {
		return nil, fmt.Errorf("BaseRegQueryInfoKey failed: 0x%08x", status)
	}

	return info, nil
}

// BaseRegQueryValue retrieves a value from a registry key
func BaseRegQueryValue(client *dcerpc.Client, hKey []byte, valueName string) (uint32, []byte, error) {
	return BaseRegQueryValueWithSize(client, hKey, valueName, 512)
}

// BaseRegQueryValueWithSize retrieves a value with specified buffer size
func BaseRegQueryValueWithSize(client *dcerpc.Client, hKey []byte, valueName string, dataLen uint32) (uint32, []byte, error) {
	buf := new(bytes.Buffer)

	// hKey (RPC_HKEY - 20 bytes)
	buf.Write(hKey)

	// lpValueName (RRP_UNICODE_STRING)
	writeRRPUnicodeString(buf, valueName)

	// For top-level parameters, each pointer is followed immediately by its deferred value
	// (unlike embedded pointers where all refs come first then all deferred)

	// lpType (LPULONG - pointer to DWORD) + deferred value
	binary.Write(buf, binary.LittleEndian, uint32(0x20000)) // Referent ID
	binary.Write(buf, binary.LittleEndian, uint32(0))       // Deferred value (initial type = 0)

	// lpData (conformant varying byte array) + deferred array
	binary.Write(buf, binary.LittleEndian, uint32(0x20004)) // Referent ID
	binary.Write(buf, binary.LittleEndian, dataLen)         // MaxCount
	binary.Write(buf, binary.LittleEndian, uint32(0))       // Offset
	binary.Write(buf, binary.LittleEndian, dataLen)         // ActualCount
	buf.Write(make([]byte, dataLen))                        // Placeholder data

	// lpcbData (LPULONG - pointer to DWORD for buffer size) + deferred value
	binary.Write(buf, binary.LittleEndian, uint32(0x20008)) // Referent ID
	binary.Write(buf, binary.LittleEndian, dataLen)         // Buffer size

	// lpcbLen (LPULONG - pointer to DWORD for actual length) + deferred value
	binary.Write(buf, binary.LittleEndian, uint32(0x2000c)) // Referent ID
	binary.Write(buf, binary.LittleEndian, dataLen)         // Initial length

	resp, err := client.Call(OpBaseRegQueryValue, buf.Bytes())
	if err != nil {
		return 0, nil, err
	}

	r := bytes.NewReader(resp)

	// Parse response
	// lpType pointer + value
	var typePtr, valueType uint32
	binary.Read(r, binary.LittleEndian, &typePtr)
	if typePtr != 0 {
		binary.Read(r, binary.LittleEndian, &valueType)
	}

	// lpData pointer + conformant array
	var dataPtr uint32
	binary.Read(r, binary.LittleEndian, &dataPtr)

	var data []byte
	if dataPtr != 0 {
		var maxCount, offset, actualCount uint32
		binary.Read(r, binary.LittleEndian, &maxCount)
		binary.Read(r, binary.LittleEndian, &offset)
		binary.Read(r, binary.LittleEndian, &actualCount)

		if actualCount > 0 {
			data = make([]byte, actualCount)
			r.Read(data)
		}
	}

	// lpcbData
	var cbDataPtr, cbData uint32
	binary.Read(r, binary.LittleEndian, &cbDataPtr)
	if cbDataPtr != 0 {
		binary.Read(r, binary.LittleEndian, &cbData)
	}

	// lpcbLen
	var cbLenPtr, cbLen uint32
	binary.Read(r, binary.LittleEndian, &cbLenPtr)
	if cbLenPtr != 0 {
		binary.Read(r, binary.LittleEndian, &cbLen)
	}

	// Status at end
	var status uint32
	binary.Read(r, binary.LittleEndian, &status)
	if status != ERROR_SUCCESS {
		// Check for ERROR_MORE_DATA and retry with larger buffer
		if status == 0xEA { // ERROR_MORE_DATA
			return BaseRegQueryValueWithSize(client, hKey, valueName, cbData)
		}
		return 0, nil, fmt.Errorf("BaseRegQueryValue(%s) failed: 0x%08x", valueName, status)
	}

	// Trim data to actual length
	if cbLen > 0 && int(cbLen) < len(data) {
		data = data[:cbLen]
	}

	return valueType, data, nil
}

// BaseRegSaveKey saves a registry key to a file
func BaseRegSaveKey(client *dcerpc.Client, hKey []byte, fileName string) error {
	buf := new(bytes.Buffer)

	// hKey
	buf.Write(hKey)

	// lpFile (RRP_UNICODE_STRING) - file path
	writeRRPUnicodeString(buf, fileName)

	// pSecurityAttributes - NULL (no special security)
	binary.Write(buf, binary.LittleEndian, uint32(0))

	resp, err := client.Call(OpBaseRegSaveKey, buf.Bytes())
	if err != nil {
		return err
	}

	if len(resp) < 4 {
		return fmt.Errorf("response too short")
	}

	status := binary.LittleEndian.Uint32(resp[len(resp)-4:])
	if status != ERROR_SUCCESS {
		return fmt.Errorf("BaseRegSaveKey(%s) failed: 0x%08x", fileName, status)
	}

	return nil
}

// BaseRegEnumKey enumerates subkeys of a registry key
func BaseRegEnumKey(client *dcerpc.Client, hKey []byte, index uint32) (string, string, error) {
	buf := new(bytes.Buffer)

	// hKey
	buf.Write(hKey)

	// dwIndex
	binary.Write(buf, binary.LittleEndian, index)

	// lpNameIn (RRP_UNICODE_STRING) - buffer for name
	maxNameLen := uint16(256 * 2) // 256 chars
	binary.Write(buf, binary.LittleEndian, uint16(0))      // Length
	binary.Write(buf, binary.LittleEndian, maxNameLen)     // MaximumLength
	binary.Write(buf, binary.LittleEndian, uint32(0x20000)) // Pointer

	// Deferred name buffer
	binary.Write(buf, binary.LittleEndian, uint32(maxNameLen/2)) // MaxCount
	binary.Write(buf, binary.LittleEndian, uint32(0))            // Offset
	binary.Write(buf, binary.LittleEndian, uint32(0))            // ActualCount

	// lpClassIn (RRP_UNICODE_STRING pointer) - optional
	binary.Write(buf, binary.LittleEndian, uint32(0x20004)) // Pointer

	// Deferred class string struct
	binary.Write(buf, binary.LittleEndian, uint16(0))       // Length
	binary.Write(buf, binary.LittleEndian, uint16(256*2))   // MaximumLength
	binary.Write(buf, binary.LittleEndian, uint32(0x20008)) // Buffer pointer

	// Deferred class buffer
	binary.Write(buf, binary.LittleEndian, uint32(256)) // MaxCount
	binary.Write(buf, binary.LittleEndian, uint32(0))   // Offset
	binary.Write(buf, binary.LittleEndian, uint32(0))   // ActualCount

	// lpftLastWriteTime (pointer) - optional
	binary.Write(buf, binary.LittleEndian, uint32(0)) // NULL

	resp, err := client.Call(OpBaseRegEnumKey, buf.Bytes())
	if err != nil {
		return "", "", err
	}

	r := bytes.NewReader(resp)

	// Parse lpNameOut
	var nameLen, nameMaxLen uint16
	var namePtr uint32
	binary.Read(r, binary.LittleEndian, &nameLen)
	binary.Read(r, binary.LittleEndian, &nameMaxLen)
	binary.Read(r, binary.LittleEndian, &namePtr)

	var keyName string
	if namePtr != 0 {
		var maxCount, offset, actualCount uint32
		binary.Read(r, binary.LittleEndian, &maxCount)
		binary.Read(r, binary.LittleEndian, &offset)
		binary.Read(r, binary.LittleEndian, &actualCount)

		if actualCount > 0 {
			chars := make([]uint16, actualCount)
			binary.Read(r, binary.LittleEndian, &chars)
			if len(chars) > 0 && chars[len(chars)-1] == 0 {
				chars = chars[:len(chars)-1]
			}
			keyName = string(utf16.Decode(chars))
		}
	}

	// Parse lpClassOut (optional)
	var classPtr uint32
	binary.Read(r, binary.LittleEndian, &classPtr)

	var className string
	if classPtr != 0 {
		var clsLen, clsMaxLen uint16
		var clsBufPtr uint32
		binary.Read(r, binary.LittleEndian, &clsLen)
		binary.Read(r, binary.LittleEndian, &clsMaxLen)
		binary.Read(r, binary.LittleEndian, &clsBufPtr)

		if clsBufPtr != 0 {
			var maxCount, offset, actualCount uint32
			binary.Read(r, binary.LittleEndian, &maxCount)
			binary.Read(r, binary.LittleEndian, &offset)
			binary.Read(r, binary.LittleEndian, &actualCount)

			if actualCount > 0 {
				chars := make([]uint16, actualCount)
				binary.Read(r, binary.LittleEndian, &chars)
				if len(chars) > 0 && chars[len(chars)-1] == 0 {
					chars = chars[:len(chars)-1]
				}
				className = string(utf16.Decode(chars))
			}
		}
	}

	// Skip to status at end
	r.Seek(-4, 2)
	var status uint32
	binary.Read(r, binary.LittleEndian, &status)

	if status == ERROR_NO_MORE_ITEMS {
		return "", "", fmt.Errorf("no more items")
	}
	if status != ERROR_SUCCESS {
		return "", "", fmt.Errorf("BaseRegEnumKey failed: 0x%08x", status)
	}

	return keyName, className, nil
}

// OpenClassesRoot opens the HKEY_CLASSES_ROOT root key
func OpenClassesRoot(client *dcerpc.Client, samDesired uint32) ([]byte, error) {
	buf := new(bytes.Buffer)

	// ServerName (PREGISTRY_SERVER_NAME) - NULL pointer
	binary.Write(buf, binary.LittleEndian, uint32(0))

	// samDesired (REGSAM)
	binary.Write(buf, binary.LittleEndian, samDesired)

	resp, err := client.Call(OpOpenClassesRoot, buf.Bytes())
	if err != nil {
		return nil, err
	}

	if len(resp) < 24 {
		return nil, fmt.Errorf("response too short: %d bytes", len(resp))
	}

	handle := make([]byte, 20)
	copy(handle, resp[:20])
	status := binary.LittleEndian.Uint32(resp[20:24])
	if status != ERROR_SUCCESS {
		return nil, fmt.Errorf("OpenClassesRoot failed: 0x%08x", status)
	}

	return handle, nil
}

// OpenCurrentUser opens the HKEY_CURRENT_USER root key
func OpenCurrentUser(client *dcerpc.Client, samDesired uint32) ([]byte, error) {
	buf := new(bytes.Buffer)

	// ServerName - NULL
	binary.Write(buf, binary.LittleEndian, uint32(0))

	// samDesired
	binary.Write(buf, binary.LittleEndian, samDesired)

	resp, err := client.Call(OpOpenCurrentUser, buf.Bytes())
	if err != nil {
		return nil, err
	}

	if len(resp) < 24 {
		return nil, fmt.Errorf("response too short: %d bytes", len(resp))
	}

	handle := make([]byte, 20)
	copy(handle, resp[:20])
	status := binary.LittleEndian.Uint32(resp[20:24])
	if status != ERROR_SUCCESS {
		return nil, fmt.Errorf("OpenCurrentUser failed: 0x%08x", status)
	}

	return handle, nil
}

// BaseRegEnumValue enumerates values of a registry key by index.
// maxNameLen is the max value name length in chars (from BaseRegQueryInfoKey.MaxValueNameLen + 1).
// maxDataLen is the max value data length in bytes (from BaseRegQueryInfoKey.MaxValueDataLen).
func BaseRegEnumValue(client *dcerpc.Client, hKey []byte, index uint32, maxNameLen, maxDataLen uint32) (string, uint32, []byte, error) {
	if maxNameLen == 0 {
		maxNameLen = 256
	}
	if maxDataLen == 0 {
		maxDataLen = 512
	}

	buf := new(bytes.Buffer)

	// hKey
	buf.Write(hKey)

	// dwIndex
	binary.Write(buf, binary.LittleEndian, index)

	// lpValueNameIn (RRP_UNICODE_STRING) - provide buffer sized for max name
	nameBufBytes := uint16((maxNameLen + 1) * 2)
	nameCharCount := uint32(maxNameLen + 1)
	binary.Write(buf, binary.LittleEndian, nameBufBytes)     // Length
	binary.Write(buf, binary.LittleEndian, nameBufBytes)     // MaximumLength
	binary.Write(buf, binary.LittleEndian, uint32(0x20000))  // Pointer

	// Deferred name buffer (conformant varying array of uint16)
	binary.Write(buf, binary.LittleEndian, nameCharCount) // MaxCount
	binary.Write(buf, binary.LittleEndian, uint32(0))     // Offset
	binary.Write(buf, binary.LittleEndian, nameCharCount) // ActualCount
	buf.Write(make([]byte, int(nameBufBytes)))             // Zero-filled buffer

	// Pad to 4-byte boundary
	if buf.Len()%4 != 0 {
		padding := 4 - (buf.Len() % 4)
		buf.Write(make([]byte, padding))
	}

	// lpType (LPDWORD pointer) + deferred value
	binary.Write(buf, binary.LittleEndian, uint32(0x20004)) // Pointer
	binary.Write(buf, binary.LittleEndian, uint32(0))       // Initial type

	// lpData (conformant varying byte array pointer) + deferred
	binary.Write(buf, binary.LittleEndian, uint32(0x20008)) // Pointer
	binary.Write(buf, binary.LittleEndian, maxDataLen)       // MaxCount
	binary.Write(buf, binary.LittleEndian, uint32(0))        // Offset
	binary.Write(buf, binary.LittleEndian, maxDataLen)       // ActualCount
	buf.Write(make([]byte, maxDataLen))                      // Placeholder data

	// Pad data to 4-byte boundary
	if buf.Len()%4 != 0 {
		padding := 4 - (buf.Len() % 4)
		buf.Write(make([]byte, padding))
	}

	// lpcbData (LPDWORD pointer) + deferred
	binary.Write(buf, binary.LittleEndian, uint32(0x2000c)) // Pointer
	binary.Write(buf, binary.LittleEndian, maxDataLen)       // Buffer size

	// lpcbLen (LPDWORD pointer) + deferred
	binary.Write(buf, binary.LittleEndian, uint32(0x20010)) // Pointer
	binary.Write(buf, binary.LittleEndian, maxDataLen)       // Initial length

	resp, err := client.Call(OpBaseRegEnumValue, buf.Bytes())
	if err != nil {
		return "", 0, nil, err
	}

	r := bytes.NewReader(resp)

	// Parse lpValueNameOut (RRP_UNICODE_STRING)
	var nameLen, nameMaxLenOut uint16
	var namePtr uint32
	binary.Read(r, binary.LittleEndian, &nameLen)
	binary.Read(r, binary.LittleEndian, &nameMaxLenOut)
	binary.Read(r, binary.LittleEndian, &namePtr)

	var valueName string
	if namePtr != 0 {
		var maxCount, offset, actualCount uint32
		binary.Read(r, binary.LittleEndian, &maxCount)
		binary.Read(r, binary.LittleEndian, &offset)
		binary.Read(r, binary.LittleEndian, &actualCount)

		if actualCount > 0 {
			chars := make([]uint16, actualCount)
			binary.Read(r, binary.LittleEndian, &chars)
			if len(chars) > 0 && chars[len(chars)-1] == 0 {
				chars = chars[:len(chars)-1]
			}
			valueName = string(utf16.Decode(chars))

			// Align to 4-byte boundary
			dataBytes := int(actualCount) * 2
			if dataBytes%4 != 0 {
				padding := 4 - (dataBytes % 4)
				r.Seek(int64(padding), 1)
			}
		}
	}

	// lpType pointer + value
	var typePtr, valueType uint32
	binary.Read(r, binary.LittleEndian, &typePtr)
	if typePtr != 0 {
		binary.Read(r, binary.LittleEndian, &valueType)
	}

	// lpData pointer + conformant array
	var dataPtr uint32
	binary.Read(r, binary.LittleEndian, &dataPtr)

	var data []byte
	if dataPtr != 0 {
		var maxCount, offset, actualCount uint32
		binary.Read(r, binary.LittleEndian, &maxCount)
		binary.Read(r, binary.LittleEndian, &offset)
		binary.Read(r, binary.LittleEndian, &actualCount)

		if actualCount > 0 {
			data = make([]byte, actualCount)
			r.Read(data)
		}
	}

	// lpcbData
	var cbDataPtr, cbData uint32
	binary.Read(r, binary.LittleEndian, &cbDataPtr)
	if cbDataPtr != 0 {
		binary.Read(r, binary.LittleEndian, &cbData)
	}

	// lpcbLen
	var cbLenPtr, cbLen uint32
	binary.Read(r, binary.LittleEndian, &cbLenPtr)
	if cbLenPtr != 0 {
		binary.Read(r, binary.LittleEndian, &cbLen)
	}

	// Status at end
	r.Seek(-4, 2)
	var status uint32
	binary.Read(r, binary.LittleEndian, &status)

	if status == ERROR_NO_MORE_ITEMS {
		return "", 0, nil, fmt.Errorf("no more items")
	}
	if status != ERROR_SUCCESS {
		return "", 0, nil, fmt.Errorf("BaseRegEnumValue failed: 0x%08x", status)
	}

	// Trim data to actual length
	if cbLen > 0 && int(cbLen) < len(data) {
		data = data[:cbLen]
	}

	return valueName, valueType, data, nil
}

// BaseRegCreateKey creates a registry subkey (or opens it if it exists)
func BaseRegCreateKey(client *dcerpc.Client, hKey []byte, subKey string, samDesired uint32) ([]byte, error) {
	buf := new(bytes.Buffer)

	// hKey (RPC_HKEY - 20 bytes)
	buf.Write(hKey)

	// lpSubKey (RRP_UNICODE_STRING)
	writeRRPUnicodeString(buf, subKey)

	// lpClass (RRP_UNICODE_STRING) - empty
	writeRRPUnicodeString(buf, "")

	// dwOptions (REG_OPTION_NON_VOLATILE = 0)
	binary.Write(buf, binary.LittleEndian, uint32(0))

	// samDesired
	binary.Write(buf, binary.LittleEndian, samDesired)

	// lpSecurityAttributes (PRPC_SECURITY_ATTRIBUTES) - NULL
	binary.Write(buf, binary.LittleEndian, uint32(0))

	// lpdwDisposition (LPDWORD pointer) + deferred
	binary.Write(buf, binary.LittleEndian, uint32(0x20000)) // Pointer
	binary.Write(buf, binary.LittleEndian, uint32(0))       // Initial value

	resp, err := client.Call(OpBaseRegCreateKey, buf.Bytes())
	if err != nil {
		return nil, err
	}

	if len(resp) < 28 {
		return nil, fmt.Errorf("response too short: %d bytes", len(resp))
	}

	// Response: phkResult (20 bytes) + lpdwDisposition pointer (4 bytes) + disposition (4 bytes) + status (4 bytes)
	// Or: phkResult (20) + lpdwDisposition (4) + status (4) = 28 minimum
	handle := make([]byte, 20)
	copy(handle, resp[:20])

	status := binary.LittleEndian.Uint32(resp[len(resp)-4:])
	if status != ERROR_SUCCESS {
		return nil, fmt.Errorf("BaseRegCreateKey(%s) failed: 0x%08x", subKey, status)
	}

	return handle, nil
}

// BaseRegDeleteKey deletes a registry subkey
func BaseRegDeleteKey(client *dcerpc.Client, hKey []byte, subKey string) error {
	buf := new(bytes.Buffer)

	// hKey
	buf.Write(hKey)

	// lpSubKey (RRP_UNICODE_STRING)
	writeRRPUnicodeString(buf, subKey)

	resp, err := client.Call(OpBaseRegDeleteKey, buf.Bytes())
	if err != nil {
		return err
	}

	if len(resp) < 4 {
		return fmt.Errorf("response too short")
	}

	status := binary.LittleEndian.Uint32(resp[len(resp)-4:])
	if status != ERROR_SUCCESS {
		return fmt.Errorf("BaseRegDeleteKey(%s) failed: 0x%08x", subKey, status)
	}

	return nil
}

// BaseRegDeleteValue deletes a registry value
func BaseRegDeleteValue(client *dcerpc.Client, hKey []byte, valueName string) error {
	buf := new(bytes.Buffer)

	// hKey
	buf.Write(hKey)

	// lpValueName (RRP_UNICODE_STRING)
	writeRRPUnicodeString(buf, valueName)

	resp, err := client.Call(OpBaseRegDeleteValue, buf.Bytes())
	if err != nil {
		return err
	}

	if len(resp) < 4 {
		return fmt.Errorf("response too short")
	}

	status := binary.LittleEndian.Uint32(resp[len(resp)-4:])
	if status != ERROR_SUCCESS {
		return fmt.Errorf("BaseRegDeleteValue(%s) failed: 0x%08x", valueName, status)
	}

	return nil
}

// BaseRegSetValue sets a registry value
func BaseRegSetValue(client *dcerpc.Client, hKey []byte, valueName string, valType uint32, data []byte) error {
	buf := new(bytes.Buffer)

	// hKey
	buf.Write(hKey)

	// lpValueName (RRP_UNICODE_STRING)
	writeRRPUnicodeString(buf, valueName)

	// dwType
	binary.Write(buf, binary.LittleEndian, valType)

	// lpData ([in, size_is(cbData)] LPBYTE - conformant byte array)
	dataLen := uint32(len(data))
	binary.Write(buf, binary.LittleEndian, dataLen) // MaxCount
	buf.Write(data)

	// Pad data to 4-byte boundary
	if buf.Len()%4 != 0 {
		padding := 4 - (buf.Len() % 4)
		buf.Write(make([]byte, padding))
	}

	// cbData (DWORD)
	binary.Write(buf, binary.LittleEndian, dataLen)

	resp, err := client.Call(OpBaseRegSetValue, buf.Bytes())
	if err != nil {
		return err
	}

	if len(resp) < 4 {
		return fmt.Errorf("response too short")
	}

	status := binary.LittleEndian.Uint32(resp[len(resp)-4:])
	if status != ERROR_SUCCESS {
		return fmt.Errorf("BaseRegSetValue(%s) failed: 0x%08x", valueName, status)
	}

	return nil
}

// writeRRPUnicodeString writes an RRP_UNICODE_STRING to the buffer
// Follows Impacket's encoding where the null terminator IS included in the data
func writeRRPUnicodeString(buf *bytes.Buffer, s string) {
	// Convert to UTF-16LE with null terminator (like Impacket's checkNullString)
	utf16Chars := utf16.Encode([]rune(s))
	utf16Chars = append(utf16Chars, 0) // Add null terminator

	// Both Length and MaximumLength include the null (matching Impacket behavior)
	byteLen := len(utf16Chars) * 2

	// RRP_UNICODE_STRING structure:
	binary.Write(buf, binary.LittleEndian, uint16(byteLen))   // Length
	binary.Write(buf, binary.LittleEndian, uint16(byteLen))   // MaximumLength
	binary.Write(buf, binary.LittleEndian, uint32(0x20000))   // Pointer (referent ID)

	// Deferred: conformant varying array
	// MaxCount = ActualCount = number of characters (including null)
	charCount := uint32(len(utf16Chars))

	binary.Write(buf, binary.LittleEndian, charCount)  // MaxCount
	binary.Write(buf, binary.LittleEndian, uint32(0))  // Offset
	binary.Write(buf, binary.LittleEndian, charCount)  // ActualCount

	// Write UTF-16LE data (including null terminator)
	for _, c := range utf16Chars {
		binary.Write(buf, binary.LittleEndian, c)
	}

	// Pad to 4-byte boundary
	if buf.Len()%4 != 0 {
		padding := 4 - (buf.Len() % 4)
		buf.Write(make([]byte, padding))
	}
}
