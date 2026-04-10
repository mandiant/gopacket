// SPDX-License-Identifier: Apache-2.0

package tds

import (
	"encoding/binary"
	"fmt"
	"math"
	"time"
)

// Token represents a parsed TDS token
type Token interface {
	TokenType() uint8
}

// ErrorToken represents a TDS_ERROR_TOKEN
type ErrorToken struct {
	Type       uint8
	Length     uint16
	Number     uint32
	State      uint8
	Class      uint8
	MsgText    string
	ServerName string
	ProcName   string
	LineNumber uint16
}

func (t *ErrorToken) TokenType() uint8 { return t.Type }

// InfoToken represents a TDS_INFO_TOKEN
type InfoToken struct {
	Type       uint8
	Length     uint16
	Number     uint32
	State      uint8
	Class      uint8
	MsgText    string
	ServerName string
	ProcName   string
	LineNumber uint16
}

func (t *InfoToken) TokenType() uint8 { return t.Type }

// LoginAckToken represents a TDS_LOGINACK_TOKEN
type LoginAckToken struct {
	Type       uint8
	Length     uint16
	Interface  uint8
	TDSVersion uint32
	ProgName   string
	MajorVer   uint8
	MinorVer   uint8
	BuildNumHi uint8
	BuildNumLo uint8
}

func (t *LoginAckToken) TokenType() uint8 { return t.Type }

// EnvChangeToken represents a TDS_ENVCHANGE_TOKEN
type EnvChangeToken struct {
	Type       uint8
	Length     uint16
	ChangeType uint8
	NewValue   string
	OldValue   string
}

func (t *EnvChangeToken) TokenType() uint8 { return t.Type }

// DoneToken represents TDS_DONE_TOKEN
type DoneToken struct {
	Type         uint8
	Status       uint16
	CurCmd       uint16
	DoneRowCount uint64
}

func (t *DoneToken) TokenType() uint8 { return t.Type }

// ReturnStatusToken represents TDS_RETURNSTATUS_TOKEN
type ReturnStatusToken struct {
	Type  uint8
	Value int32
}

func (t *ReturnStatusToken) TokenType() uint8 { return t.Type }

// ColMetaDataToken represents TDS_COLMETADATA_TOKEN
type ColMetaDataToken struct {
	Type    uint8
	Columns []ColumnInfo
}

func (t *ColMetaDataToken) TokenType() uint8 { return t.Type }

// ColumnInfo describes a column
type ColumnInfo struct {
	UserType uint16
	Flags    uint16
	ColType  uint8
	TypeData interface{}
	Name     string
	Length   int
}

// RowToken represents TDS_ROW_TOKEN
type RowToken struct {
	Type   uint8
	Values []interface{}
}

func (t *RowToken) TokenType() uint8 { return t.Type }

// SSPIToken represents TDS_SSPI_TOKEN
type SSPIToken struct {
	Type uint8
	Data []byte
}

func (t *SSPIToken) TokenType() uint8 { return t.Type }

// parseInfoError parses ERROR and INFO tokens (same structure)
func parseInfoError(data []byte) (*ErrorToken, int, error) {
	if len(data) < 3 {
		return nil, 0, fmt.Errorf("info/error token too short")
	}

	t := &ErrorToken{
		Type:   data[0],
		Length: binary.LittleEndian.Uint16(data[1:3]),
	}

	if len(data) < int(t.Length)+3 {
		return nil, 0, fmt.Errorf("info/error token data too short")
	}

	offset := 3
	t.Number = binary.LittleEndian.Uint32(data[offset:])
	offset += 4
	t.State = data[offset]
	offset++
	t.Class = data[offset]
	offset++

	// MsgText
	msgLen := binary.LittleEndian.Uint16(data[offset:])
	offset += 2
	t.MsgText = decodeUTF16LE(data[offset : offset+int(msgLen)*2])
	offset += int(msgLen) * 2

	// ServerName
	serverLen := data[offset]
	offset++
	t.ServerName = decodeUTF16LE(data[offset : offset+int(serverLen)*2])
	offset += int(serverLen) * 2

	// ProcName
	procLen := data[offset]
	offset++
	t.ProcName = decodeUTF16LE(data[offset : offset+int(procLen)*2])
	offset += int(procLen) * 2

	// LineNumber
	t.LineNumber = binary.LittleEndian.Uint16(data[offset:])

	return t, int(t.Length) + 3, nil
}

// parseLoginAck parses LOGINACK token
func parseLoginAck(data []byte) (*LoginAckToken, int, error) {
	if len(data) < 3 {
		return nil, 0, fmt.Errorf("loginack token too short")
	}

	t := &LoginAckToken{
		Type:   data[0],
		Length: binary.LittleEndian.Uint16(data[1:3]),
	}

	offset := 3
	t.Interface = data[offset]
	offset++
	t.TDSVersion = binary.LittleEndian.Uint32(data[offset:])
	offset += 4

	// ProgName
	progLen := data[offset]
	offset++
	t.ProgName = decodeUTF16LE(data[offset : offset+int(progLen)*2])
	offset += int(progLen) * 2

	t.MajorVer = data[offset]
	offset++
	t.MinorVer = data[offset]
	offset++
	t.BuildNumHi = data[offset]
	offset++
	t.BuildNumLo = data[offset]

	return t, int(t.Length) + 3, nil
}

// parseEnvChange parses ENVCHANGE token
func parseEnvChange(data []byte) (*EnvChangeToken, int, error) {
	if len(data) < 4 {
		return nil, 0, fmt.Errorf("envchange token too short")
	}

	t := &EnvChangeToken{
		Type:   data[0],
		Length: binary.LittleEndian.Uint16(data[1:3]),
	}

	offset := 3
	t.ChangeType = data[offset]
	offset++

	// Parse based on change type
	switch t.ChangeType {
	case TDSEnvChangeDatabase, TDSEnvChangeLanguage, TDSEnvChangeCharset, TDSEnvChangePacketSize:
		// VARCHAR format
		newLen := data[offset]
		offset++
		t.NewValue = decodeUTF16LE(data[offset : offset+int(newLen)*2])
		offset += int(newLen) * 2

		oldLen := data[offset]
		offset++
		if oldLen > 0 {
			t.OldValue = decodeUTF16LE(data[offset : offset+int(oldLen)*2])
		}
	default:
		// Skip unknown types
	}

	return t, int(t.Length) + 3, nil
}

// parseDone parses DONE, DONEPROC, DONEINPROC tokens
func parseDone(data []byte) (*DoneToken, int, error) {
	if len(data) < 9 {
		return nil, 0, fmt.Errorf("done token too short")
	}

	t := &DoneToken{
		Type:         data[0],
		Status:       binary.LittleEndian.Uint16(data[1:3]),
		CurCmd:       binary.LittleEndian.Uint16(data[3:5]),
		DoneRowCount: uint64(binary.LittleEndian.Uint32(data[5:9])),
	}

	return t, 9, nil
}

// parseReturnStatus parses RETURNSTATUS token
func parseReturnStatus(data []byte) (*ReturnStatusToken, int, error) {
	if len(data) < 5 {
		return nil, 0, fmt.Errorf("returnstatus token too short")
	}

	t := &ReturnStatusToken{
		Type:  data[0],
		Value: int32(binary.LittleEndian.Uint32(data[1:5])),
	}

	return t, 5, nil
}

// parseSSPI parses SSPI token
func parseSSPI(data []byte) (*SSPIToken, int, error) {
	if len(data) < 3 {
		return nil, 0, fmt.Errorf("sspi token too short")
	}

	length := binary.LittleEndian.Uint16(data[1:3])
	t := &SSPIToken{
		Type: data[0],
		Data: data[3 : 3+length],
	}

	return t, 3 + int(length), nil
}

// parseColMetaData parses COLMETADATA token
func parseColMetaData(data []byte) (*ColMetaDataToken, int, error) {
	if len(data) < 3 {
		return nil, 0, fmt.Errorf("colmetadata token too short")
	}

	t := &ColMetaDataToken{
		Type: data[0],
	}

	count := binary.LittleEndian.Uint16(data[1:3])
	if count == 0xFFFF {
		return t, 3, nil
	}

	offset := 3
	for i := 0; i < int(count); i++ {
		col := ColumnInfo{}

		// UserType
		col.UserType = binary.LittleEndian.Uint16(data[offset:])
		offset += 2

		// Flags
		col.Flags = binary.LittleEndian.Uint16(data[offset:])
		offset += 2

		// Type
		col.ColType = data[offset]
		offset++

		// TypeData based on type
		switch col.ColType {
		case TDSBitType, TDSInt1Type, TDSInt2Type, TDSInt4Type, TDSInt8Type,
			TDSDateTimeType, TDSDateTim4Type, TDSFlt4Type, TDSFlt8Type,
			TDSMoneyType, TDSMoney4Type, TDSDateNType:
			// No type data
		case TDSIntNType, TDSTimeNType, TDSDateTime2NType, TDSDateTimeOffsetNType,
			TDSFltNType, TDSMoneyNType, TDSGuidType, TDSBitNType, TDSDateTimNType:
			col.TypeData = data[offset]
			offset++
		case TDSBigVarBinType, TDSBigBinaryType, TDSNCharType, TDSNVarCharType,
			TDSBigVarChrType, TDSBigCharType:
			col.TypeData = binary.LittleEndian.Uint16(data[offset:])
			offset += 2
		case TDSDecimalNType, TDSNumericNType, TDSDecimalType:
			col.TypeData = data[offset : offset+3]
			offset += 3
		case TDSImageType, TDSTextType, TDSXMLType, TDSSSVariantType, TDSNTextType:
			col.TypeData = binary.LittleEndian.Uint32(data[offset:])
			offset += 4
		}

		// Collation for certain types
		switch col.ColType {
		case TDSNTextType, TDSBigCharType, TDSBigVarChrType, TDSNCharType, TDSNVarCharType, TDSTextType:
			offset += 5 // Skip collation
		}

		// PartTableName for certain types
		switch col.ColType {
		case TDSImageType, TDSTextType, TDSNTextType:
			tableLen := binary.LittleEndian.Uint16(data[offset:])
			offset += 2
			offset += int(tableLen) * 2
		}

		// Column name
		nameLen := data[offset]
		offset++
		col.Name = decodeUTF16LE(data[offset : offset+int(nameLen)*2])
		offset += int(nameLen) * 2

		t.Columns = append(t.Columns, col)
	}

	return t, offset, nil
}

// parseRow parses a ROW token using column metadata
func parseRow(data []byte, columns []ColumnInfo) (*RowToken, int, error) {
	t := &RowToken{
		Type: data[0],
	}

	offset := 1
	for _, col := range columns {
		var value interface{}
		var consumed int

		switch col.ColType {
		case TDSNVarCharType, TDSNCharType:
			charLen := binary.LittleEndian.Uint16(data[offset:])
			offset += 2
			if charLen != 0xFFFF {
				value = decodeUTF16LE(data[offset : offset+int(charLen)])
				offset += int(charLen)
			} else {
				value = nil
			}

		case TDSBigVarChrType:
			charLen := binary.LittleEndian.Uint16(data[offset:])
			offset += 2
			if charLen != 0xFFFF {
				value = string(data[offset : offset+int(charLen)])
				offset += int(charLen)
			} else {
				value = nil
			}

		case TDSGuidType:
			uuidLen := data[offset]
			offset++
			if uuidLen > 0 {
				value = data[offset : offset+int(uuidLen)]
				offset += int(uuidLen)
			} else {
				value = nil
			}

		case TDSNTextType, TDSImageType:
			ptrLen := data[offset]
			offset++
			if ptrLen == 0 {
				value = nil
			} else {
				offset += int(ptrLen) + 8 // Skip pointer and timestamp
				charLen := binary.LittleEndian.Uint32(data[offset:])
				offset += 4
				if col.ColType == TDSNTextType {
					value = decodeUTF16LE(data[offset : offset+int(charLen)])
				} else {
					value = data[offset : offset+int(charLen)]
				}
				offset += int(charLen)
			}

		case TDSTextType:
			ptrLen := data[offset]
			offset++
			if ptrLen == 0 {
				value = nil
			} else {
				offset += int(ptrLen) + 8
				charLen := binary.LittleEndian.Uint32(data[offset:])
				offset += 4
				value = string(data[offset : offset+int(charLen)])
				offset += int(charLen)
			}

		case TDSBigVarBinType, TDSBigBinaryType:
			charLen := binary.LittleEndian.Uint16(data[offset:])
			offset += 2
			if charLen != 0xFFFF {
				value = data[offset : offset+int(charLen)]
				offset += int(charLen)
			} else {
				value = nil
			}

		case TDSDateTimNType:
			valSize := data[offset]
			offset++
			if valSize == 0 {
				value = nil
			} else if valSize == 4 {
				// smalldatetime
				dateVal := binary.LittleEndian.Uint16(data[offset:])
				offset += 2
				timeVal := binary.LittleEndian.Uint16(data[offset:])
				offset += 2
				baseDate := time.Date(1900, 1, 1, 0, 0, 0, 0, time.UTC)
				value = baseDate.AddDate(0, 0, int(dateVal)).Add(time.Duration(timeVal) * time.Minute)
			} else if valSize == 8 {
				// datetime
				dateVal := int32(binary.LittleEndian.Uint32(data[offset:]))
				offset += 4
				timeVal := binary.LittleEndian.Uint32(data[offset:])
				offset += 4
				var baseDate time.Time
				if dateVal < 0 {
					baseDate = time.Date(1753, 1, 1, 0, 0, 0, 0, time.UTC)
				} else {
					baseDate = time.Date(1900, 1, 1, 0, 0, 0, 0, time.UTC)
				}
				value = baseDate.AddDate(0, 0, int(dateVal)).Add(time.Duration(timeVal) * time.Second / 300)
			}

		case TDSDateTimeType:
			dateVal := int32(binary.LittleEndian.Uint32(data[offset:]))
			offset += 4
			timeVal := binary.LittleEndian.Uint32(data[offset:])
			offset += 4
			var baseDate time.Time
			if dateVal < 0 {
				baseDate = time.Date(1753, 1, 1, 0, 0, 0, 0, time.UTC)
			} else {
				baseDate = time.Date(1900, 1, 1, 0, 0, 0, 0, time.UTC)
			}
			value = baseDate.AddDate(0, 0, int(dateVal)).Add(time.Duration(timeVal) * time.Second / 300)

		case TDSDateTim4Type:
			dateVal := binary.LittleEndian.Uint16(data[offset:])
			offset += 2
			timeVal := binary.LittleEndian.Uint16(data[offset:])
			offset += 2
			baseDate := time.Date(1900, 1, 1, 0, 0, 0, 0, time.UTC)
			value = baseDate.AddDate(0, 0, int(dateVal)).Add(time.Duration(timeVal) * time.Minute)

		case TDSInt4Type, TDSMoney4Type, TDSFlt4Type:
			value = int32(binary.LittleEndian.Uint32(data[offset:]))
			offset += 4

		case TDSFltNType:
			valSize := data[offset]
			offset++
			if valSize == 0 {
				value = nil
			} else if valSize == 4 {
				bits := binary.LittleEndian.Uint32(data[offset:])
				value = math.Float32frombits(bits)
				offset += 4
			} else if valSize == 8 {
				bits := binary.LittleEndian.Uint64(data[offset:])
				value = math.Float64frombits(bits)
				offset += 8
			}

		case TDSMoneyNType:
			valSize := data[offset]
			offset++
			if valSize == 0 {
				value = nil
			} else if valSize == 4 {
				val := int32(binary.LittleEndian.Uint32(data[offset:]))
				value = float64(val) / 10000.0
				offset += 4
			} else if valSize == 8 {
				val := int64(binary.LittleEndian.Uint64(data[offset:]))
				value = float64(val>>32) / 10000.0
				offset += 8
			}

		case TDSBigCharType:
			charLen := binary.LittleEndian.Uint16(data[offset:])
			offset += 2
			value = string(data[offset : offset+int(charLen)])
			offset += int(charLen)

		case TDSInt8Type, TDSFlt8Type, TDSMoneyType:
			value = int64(binary.LittleEndian.Uint64(data[offset:]))
			offset += 8

		case TDSInt2Type:
			value = int16(binary.LittleEndian.Uint16(data[offset:]))
			offset += 2

		case TDSBitType, TDSInt1Type:
			value = data[offset]
			offset++

		case TDSIntNType:
			valSize := data[offset]
			offset++
			if valSize == 0 {
				value = nil
			} else if valSize == 1 {
				value = int8(data[offset])
				offset++
			} else if valSize == 2 {
				value = int16(binary.LittleEndian.Uint16(data[offset:]))
				offset += 2
			} else if valSize == 4 {
				value = int32(binary.LittleEndian.Uint32(data[offset:]))
				offset += 4
			} else if valSize == 8 {
				value = int64(binary.LittleEndian.Uint64(data[offset:]))
				offset += 8
			}

		case TDSBitNType:
			valSize := data[offset]
			offset++
			if valSize == 0 {
				value = nil
			} else {
				value = data[offset]
				offset++
			}

		case TDSNumericNType, TDSDecimalNType:
			valLen := data[offset]
			offset++
			if valLen == 0 {
				value = nil
			} else {
				// Just store raw bytes for now
				value = data[offset : offset+int(valLen)]
				offset += int(valLen)
			}

		default:
			// Unknown type, try to skip
			value = nil
			consumed = 0
		}

		_ = consumed
		t.Values = append(t.Values, value)
	}

	return t, offset, nil
}

// ParseTokens parses all tokens from TDS response data
func ParseTokens(data []byte, columns []ColumnInfo) ([]Token, []ColumnInfo, error) {
	var tokens []Token
	currentColumns := columns

	offset := 0
	for offset < len(data) {
		tokenID := data[offset]

		var token Token
		var consumed int
		var err error

		switch tokenID {
		case TDSErrorToken:
			var t *ErrorToken
			t, consumed, err = parseInfoError(data[offset:])
			token = t
		case TDSInfoToken:
			var t *ErrorToken
			t, consumed, err = parseInfoError(data[offset:])
			// Convert to InfoToken
			token = &InfoToken{
				Type:       t.Type,
				Length:     t.Length,
				Number:     t.Number,
				State:      t.State,
				Class:      t.Class,
				MsgText:    t.MsgText,
				ServerName: t.ServerName,
				ProcName:   t.ProcName,
				LineNumber: t.LineNumber,
			}
		case TDSLoginAckToken:
			var t *LoginAckToken
			t, consumed, err = parseLoginAck(data[offset:])
			token = t
		case TDSEnvChangeToken:
			var t *EnvChangeToken
			t, consumed, err = parseEnvChange(data[offset:])
			token = t
		case TDSDoneToken, TDSDoneProcToken, TDSDoneInProcToken:
			var t *DoneToken
			t, consumed, err = parseDone(data[offset:])
			token = t
		case TDSReturnStatusToken:
			var t *ReturnStatusToken
			t, consumed, err = parseReturnStatus(data[offset:])
			token = t
		case TDSColMetadataToken:
			var t *ColMetaDataToken
			t, consumed, err = parseColMetaData(data[offset:])
			if t != nil {
				currentColumns = t.Columns
			}
			token = t
		case TDSRowToken:
			var t *RowToken
			t, consumed, err = parseRow(data[offset:], currentColumns)
			token = t
		case TDSSSPIToken:
			var t *SSPIToken
			t, consumed, err = parseSSPI(data[offset:])
			token = t
		case TDSOrderToken:
			// Skip order token
			if len(data) > offset+3 {
				length := binary.LittleEndian.Uint16(data[offset+1:])
				consumed = 3 + int(length)
			}
		default:
			// Unknown token, stop parsing
			return tokens, currentColumns, fmt.Errorf("unknown token: 0x%02x at offset %d", tokenID, offset)
		}

		if err != nil {
			return tokens, currentColumns, err
		}

		if token != nil {
			tokens = append(tokens, token)
		}
		offset += consumed
	}

	return tokens, currentColumns, nil
}
