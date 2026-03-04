// Package icpr implements the MS-ICPR (ICertPassage Remote Protocol) interface.
// This is used for certificate enrollment via DCE/RPC, as an alternative to
// HTTP-based AD CS enrollment (ESC8).
// Reference: [MS-ICPR] https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-icpr
package icpr

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"unicode/utf16"

	"gopacket/internal/build"
	"gopacket/pkg/dcerpc"
	"log"
)

// UUID is the ICPR interface UUID: 91ae6020-9e3c-11cf-8d7c-00aa00c091be
var UUID = [16]byte{
	0x20, 0x60, 0xae, 0x91, 0x3c, 0x9e, 0xcf, 0x11,
	0x8d, 0x7c, 0x00, 0xaa, 0x00, 0xc0, 0x91, 0xbe,
}

const MajorVersion = 0
const MinorVersion = 0

// Operation numbers
const (
	OpCertServerRequest = 0 // CertServerRequest
)

// Disposition codes from CertServerRequest response
const (
	DispositionIssued           = 3 // CR_DISP_ISSUED — certificate issued
	DispositionIssuedOutOfBand  = 4 // CR_DISP_ISSUED_OUT_OF_BAND
	DispositionUnderSubmission  = 5 // CR_DISP_UNDER_SUBMISSION — pending approval
)

// CertServerRequest calls ICertPassage::CertServerRequest (opnum 0).
// Sends a CSR to the CA and returns the issued certificate DER bytes.
//
// Parameters:
//   - client: authenticated DCE/RPC client bound to the ICPR interface
//   - caName: CA name (e.g., "ESSOS-CA")
//   - csrDER: DER-encoded PKCS#10 certificate signing request
//   - attributes: list of attributes (e.g., ["CertificateTemplate:Machine"])
//
// Returns the DER-encoded certificate bytes on success.
func CertServerRequest(client *dcerpc.Client, caName string, csrDER []byte, attributes []string) ([]byte, uint32, error) {
	// Build attribute string: join with \n, null-terminate, encode as UTF-16LE
	attrStr := ""
	for i, a := range attributes {
		if i > 0 {
			attrStr += "\n"
		}
		attrStr += a
	}
	attrBytes := encodeUTF16LE(attrStr)

	// Build NDR request
	payload := buildCertServerRequest(caName, csrDER, attrBytes)

	if build.Debug {
		log.Printf("[D] ICPR: sending CertServerRequest (CA=%s, CSR=%d bytes, attrs=%d bytes)",
			caName, len(csrDER), len(attrBytes))
	}

	resp, err := client.Call(OpCertServerRequest, payload)
	if err != nil {
		return nil, 0, fmt.Errorf("CertServerRequest call failed: %v", err)
	}

	return parseCertServerResponse(resp)
}

// buildCertServerRequest constructs the NDR-encoded request for CertServerRequest.
//
// Wire format (NDR):
//   dwFlags:        DWORD (inline)
//   pwszAuthority:  LPWSTR — unique pointer to conformant varying string
//   pdwRequestId:   LPDWORD — unique pointer to DWORD
//   pctbAttribs:    CERTTRANSBLOB — embedded struct (cb + pb pointer)
//   pctbRequest:    CERTTRANSBLOB — embedded struct (cb + pb pointer)
//
// Deferred pointer data follows inline data in referent ID order.
func buildCertServerRequest(caName string, csrDER, attrBytes []byte) []byte {
	var buf bytes.Buffer

	// Incrementing referent IDs for unique pointers
	refID := uint32(0x00020000)

	// --- Inline portion ---

	// dwFlags: DWORD = 0
	binary.Write(&buf, binary.LittleEndian, uint32(0))

	// pwszAuthority: LPWSTR (unique pointer)
	authorityRefID := refID
	binary.Write(&buf, binary.LittleEndian, authorityRefID)
	refID += 4

	// pdwRequestId: LPDWORD (unique pointer)
	requestIdRefID := refID
	binary.Write(&buf, binary.LittleEndian, requestIdRefID)
	refID += 4

	// pctbAttribs: CERTTRANSBLOB (embedded struct)
	// cb (ULONG)
	binary.Write(&buf, binary.LittleEndian, uint32(len(attrBytes)))
	// pb (unique pointer to byte array)
	var attribsRefID uint32
	if len(attrBytes) > 0 {
		attribsRefID = refID
		binary.Write(&buf, binary.LittleEndian, attribsRefID)
		refID += 4
	} else {
		binary.Write(&buf, binary.LittleEndian, uint32(0)) // null pointer
	}

	// pctbRequest: CERTTRANSBLOB (embedded struct)
	// cb (ULONG)
	binary.Write(&buf, binary.LittleEndian, uint32(len(csrDER)))
	// pb (unique pointer to byte array)
	var requestRefID uint32
	if len(csrDER) > 0 {
		requestRefID = refID
		binary.Write(&buf, binary.LittleEndian, requestRefID)
		refID += 4
	} else {
		binary.Write(&buf, binary.LittleEndian, uint32(0)) // null pointer
	}

	// --- Deferred portion (in referent ID order) ---

	// pwszAuthority string data
	_ = authorityRefID
	writeConformantVaryingString(&buf, caName)

	// pdwRequestId value
	_ = requestIdRefID
	binary.Write(&buf, binary.LittleEndian, uint32(0)) // request ID = 0

	// pctbAttribs.pb byte array data
	if len(attrBytes) > 0 {
		_ = attribsRefID
		writeConformantByteArray(&buf, attrBytes)
	}

	// pctbRequest.pb byte array data
	if len(csrDER) > 0 {
		_ = requestRefID
		writeConformantByteArray(&buf, csrDER)
	}

	return buf.Bytes()
}

// parseCertServerResponse parses the NDR response from CertServerRequest.
//
// Response format:
//   pdwRequestId:          DWORD
//   pdwDisposition:        ULONG
//   pctbCert:              CERTTRANSBLOB
//   pctbEncodedCert:       CERTTRANSBLOB (contains the DER certificate)
//   pctbDispositionMessage: CERTTRANSBLOB
//   Return value:          HRESULT (4 bytes at end)
func parseCertServerResponse(resp []byte) ([]byte, uint32, error) {
	if len(resp) < 8 {
		return nil, 0, fmt.Errorf("response too short: %d bytes", len(resp))
	}

	r := bytes.NewReader(resp)

	// pdwRequestId
	var requestID uint32
	binary.Read(r, binary.LittleEndian, &requestID)

	// pdwDisposition
	var disposition uint32
	binary.Read(r, binary.LittleEndian, &disposition)

	if build.Debug {
		log.Printf("[D] ICPR: response requestID=%d, disposition=%d", requestID, disposition)
	}

	// pctbCert: CERTTRANSBLOB (skip it)
	if err := skipCertTransBlob(r); err != nil {
		return nil, disposition, fmt.Errorf("skip pctbCert: %v", err)
	}

	// pctbEncodedCert: CERTTRANSBLOB (we want this)
	var encodedCertCb uint32
	binary.Read(r, binary.LittleEndian, &encodedCertCb)
	var encodedCertPtr uint32
	binary.Read(r, binary.LittleEndian, &encodedCertPtr)

	// pctbDispositionMessage: CERTTRANSBLOB (skip inline)
	var dispositionMsgCb uint32
	binary.Read(r, binary.LittleEndian, &dispositionMsgCb)
	var dispositionMsgPtr uint32
	binary.Read(r, binary.LittleEndian, &dispositionMsgPtr)

	// Now read deferred pointer data in order:
	// 1. pctbCert.pb data (already skipped inline, skip deferred too)
	// Actually, the inline portion of the first CERTTRANSBLOB has its own pointer.
	// We need to read deferred data carefully.

	// The deferred data comes after all inline fields.
	// We need to read: pctbCert.pb data, pctbEncodedCert.pb data, pctbDispositionMessage.pb data

	// pctbCert deferred — we already read its cb and ptr during skip
	// Read the first deferred blob (pctbCert)
	_ = readDeferredByteArray(r)

	// pctbEncodedCert deferred — this is the certificate
	var certDER []byte
	if encodedCertPtr != 0 {
		certDER = readDeferredByteArray(r)
	}

	// Check disposition
	if disposition != DispositionIssued && disposition != DispositionIssuedOutOfBand {
		// Read disposition message for error reporting
		var dispMsg string
		if dispositionMsgPtr != 0 {
			msgBytes := readDeferredByteArray(r)
			if len(msgBytes) > 0 {
				dispMsg = decodeUTF16LEBytes(msgBytes)
			}
		}

		if disposition == DispositionUnderSubmission {
			return nil, requestID, fmt.Errorf("certificate request pending approval (requestID=%d)", requestID)
		}

		return nil, requestID, fmt.Errorf("certificate request failed: disposition=%d (0x%08X), message=%s",
			disposition, disposition, dispMsg)
	}

	if len(certDER) == 0 {
		return nil, requestID, fmt.Errorf("certificate issued but response is empty")
	}

	return certDER, requestID, nil
}

// skipCertTransBlob reads and discards a CERTTRANSBLOB inline portion (cb + pb pointer).
func skipCertTransBlob(r *bytes.Reader) error {
	var cb, ptr uint32
	if err := binary.Read(r, binary.LittleEndian, &cb); err != nil {
		return err
	}
	if err := binary.Read(r, binary.LittleEndian, &ptr); err != nil {
		return err
	}
	return nil
}

// readDeferredByteArray reads a deferred conformant byte array: MaxCount(4) + data.
func readDeferredByteArray(r *bytes.Reader) []byte {
	var maxCount uint32
	if err := binary.Read(r, binary.LittleEndian, &maxCount); err != nil {
		return nil
	}
	if maxCount == 0 {
		return nil
	}
	if maxCount > 1024*1024 { // sanity check: 1MB max
		return nil
	}

	data := make([]byte, maxCount)
	if _, err := r.Read(data); err != nil {
		return nil
	}

	// Skip padding to 4-byte alignment
	pad := (4 - (int(maxCount) % 4)) % 4
	if pad > 0 {
		r.Seek(int64(pad), 1)
	}

	return data
}

// writeConformantVaryingString writes a conformant varying string in NDR format.
// MaxCount(4) + Offset(4) + ActualCount(4) + UTF-16LE data + padding
func writeConformantVaryingString(buf *bytes.Buffer, s string) {
	runes := utf16.Encode([]rune(s))
	runes = append(runes, 0) // null terminator
	count := uint32(len(runes))

	binary.Write(buf, binary.LittleEndian, count)    // MaxCount
	binary.Write(buf, binary.LittleEndian, uint32(0)) // Offset
	binary.Write(buf, binary.LittleEndian, count)    // ActualCount
	for _, r := range runes {
		binary.Write(buf, binary.LittleEndian, r)
	}

	// Pad to 4-byte alignment
	dataLen := int(count) * 2
	pad := (4 - (dataLen % 4)) % 4
	for i := 0; i < pad; i++ {
		buf.WriteByte(0)
	}
}

// writeConformantByteArray writes a conformant byte array in NDR format.
// MaxCount(4) + data + padding
func writeConformantByteArray(buf *bytes.Buffer, data []byte) {
	binary.Write(buf, binary.LittleEndian, uint32(len(data))) // MaxCount
	buf.Write(data)

	// Pad to 4-byte alignment
	pad := (4 - (len(data) % 4)) % 4
	for i := 0; i < pad; i++ {
		buf.WriteByte(0)
	}
}

// encodeUTF16LE encodes a string as UTF-16LE with null terminator.
func encodeUTF16LE(s string) []byte {
	runes := utf16.Encode([]rune(s))
	runes = append(runes, 0) // null terminator
	buf := make([]byte, len(runes)*2)
	for i, r := range runes {
		binary.LittleEndian.PutUint16(buf[i*2:], r)
	}
	return buf
}

// decodeUTF16LEBytes decodes UTF-16LE bytes to a Go string.
func decodeUTF16LEBytes(b []byte) string {
	if len(b) < 2 {
		return ""
	}
	// Trim trailing null terminators
	for len(b) >= 2 && b[len(b)-2] == 0 && b[len(b)-1] == 0 {
		b = b[:len(b)-2]
	}
	runes := make([]rune, len(b)/2)
	for i := range runes {
		runes[i] = rune(binary.LittleEndian.Uint16(b[i*2:]))
	}
	return string(runes)
}
