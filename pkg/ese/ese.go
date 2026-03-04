package ese

import (
	"encoding/binary"
	"fmt"
)

// ESE database file signatures and constants
const (
	ESE_SIGNATURE = 0x89ABCDEF
)

// Page Flags
const (
	FLAGS_ROOT         = 0x0001
	FLAGS_LEAF         = 0x0002
	FLAGS_PARENT       = 0x0004
	FLAGS_EMPTY        = 0x0008
	FLAGS_SPACE_TREE   = 0x0020
	FLAGS_INDEX        = 0x0040
	FLAGS_LONG_VALUE   = 0x0080
	FLAGS_NEW_CHECKSUM = 0x2000
	FLAGS_NEW_FORMAT   = 0x8000
)

// Tag Flags
const (
	TAG_COMMON = 0x4
)

// Catalog types
const (
	CATALOG_TYPE_TABLE      = 1
	CATALOG_TYPE_COLUMN     = 2
	CATALOG_TYPE_INDEX      = 3
	CATALOG_TYPE_LONG_VALUE = 4
)

// Column Types
const (
	JET_coltypNil          = 0
	JET_coltypBit          = 1
	JET_coltypUnsignedByte = 2
	JET_coltypShort        = 3
	JET_coltypLong         = 4
	JET_coltypCurrency     = 5
	JET_coltypIEEESingle   = 6
	JET_coltypIEEEDouble   = 7
	JET_coltypDateTime     = 8
	JET_coltypBinary       = 9
	JET_coltypText         = 10
	JET_coltypLongBinary   = 11
	JET_coltypLongText     = 12
	JET_coltypSLV          = 13
	JET_coltypUnsignedLong = 14
	JET_coltypLongLong     = 15
	JET_coltypGUID         = 16
	JET_coltypUnsignedShort = 17
)

// ColumnTypeName returns the human-readable name for a column type
func ColumnTypeName(colType uint32) string {
	names := map[uint32]string{
		JET_coltypNil:          "NULL",
		JET_coltypBit:          "Boolean",
		JET_coltypUnsignedByte: "Unsigned byte",
		JET_coltypShort:        "Signed short",
		JET_coltypLong:         "Signed long",
		JET_coltypCurrency:     "Currency",
		JET_coltypIEEESingle:   "Single precision FP",
		JET_coltypIEEEDouble:   "Double precision FP",
		JET_coltypDateTime:     "DateTime",
		JET_coltypBinary:       "Binary",
		JET_coltypText:         "Text",
		JET_coltypLongBinary:   "Long Binary",
		JET_coltypLongText:     "Long Text",
		JET_coltypSLV:          "Obsolete",
		JET_coltypUnsignedLong: "Unsigned long",
		JET_coltypLongLong:     "Long long",
		JET_coltypGUID:         "GUID",
		JET_coltypUnsignedShort: "Unsigned short",
	}
	if name, ok := names[colType]; ok {
		return name
	}
	return fmt.Sprintf("Unknown(%d)", colType)
}

// DatabaseInfo contains basic database information
type DatabaseInfo struct {
	Version        uint32
	FormatRevision uint32
	PageSize       uint32
	NumPages       uint32
}

// PageInfo contains page header information
type PageInfo struct {
	Flags         uint32
	PrevPage      uint32
	NextPage      uint32
	FirstAvailTag uint16
}

// Database represents an ESE database
type Database struct {
	data           []byte
	pageSize       uint32
	version        uint32
	formatRevision uint32
	headerSize     int
	tables         map[string]*TableDef
	indexes        map[string][]string // table name -> index names
	columnNameToID map[string]uint32   // column name -> ESE column ID
}

// TableDef represents a table definition
type TableDef struct {
	Name               string
	TableID            uint32
	FatherDataPageNum  uint32
	Columns            map[uint32]*ColumnDef // ESE column ID -> column def
	ColumnsByName      map[string]*ColumnDef // column name -> column def
	db                 *Database
}

// ColumnDef represents a column definition
type ColumnDef struct {
	ID         uint32 // ESE column ID (not AD attribute ID)
	Name       string
	Type       uint32
	SpaceUsage uint32
}

// Table represents an opened table for record access
type Table struct {
	def     *TableDef
	db      *Database
	records []*Record
}

// Record represents a row from a table
type Record struct {
	columns map[string][]byte
}

// Open parses an ESE database from bytes
func Open(data []byte) (*Database, error) {
	if len(data) < 8192 {
		return nil, fmt.Errorf("database too small: %d bytes", len(data))
	}

	db := &Database{
		data:           data,
		pageSize:       8192,
		headerSize:     40,
		tables:         make(map[string]*TableDef),
		indexes:        make(map[string][]string),
		columnNameToID: make(map[string]uint32),
	}

	// Parse database header (page 0)
	if err := db.parseHeader(); err != nil {
		return nil, fmt.Errorf("failed to parse header: %v", err)
	}

	// Parse catalog to get table definitions and column mappings
	if err := db.parseCatalog(); err != nil {
		return nil, fmt.Errorf("failed to parse catalog: %v", err)
	}

	return db, nil
}

// parseHeader parses the database header
func (db *Database) parseHeader() error {
	if len(db.data) < 256 {
		return fmt.Errorf("header too short")
	}

	signature := binary.LittleEndian.Uint32(db.data[4:8])
	if signature != ESE_SIGNATURE {
		return fmt.Errorf("invalid signature: 0x%x (expected 0x%x)", signature, ESE_SIGNATURE)
	}

	db.version = binary.LittleEndian.Uint32(db.data[8:12])
	db.formatRevision = binary.LittleEndian.Uint32(db.data[0xE8:0xEC])

	// Page size is at offset 236
	pageSize := binary.LittleEndian.Uint32(db.data[236:240])
	if pageSize >= 4096 && pageSize <= 32768 {
		db.pageSize = pageSize
	}

	// Determine header size based on version
	db.headerSize = 40
	if db.pageSize > 8192 && db.version >= 0x620 && db.formatRevision >= 0x11 {
		db.headerSize = 80
	}

	return nil
}

// parseCatalog parses the system catalog to get table and column definitions
func (db *Database) parseCatalog() error {
	numPages := uint32(len(db.data)) / db.pageSize
	datatableTableID := uint32(0)

	// Scan all leaf pages for catalog entries
	for pageNum := uint32(1); pageNum < numPages; pageNum++ {
		pageData := db.getPageData(pageNum)
		if pageData == nil {
			continue
		}

		pageFlags := binary.LittleEndian.Uint32(pageData[36:40])

		// Only process leaf pages
		if pageFlags&FLAGS_LEAF == 0 {
			continue
		}

		firstAvailTag := int(binary.LittleEndian.Uint16(pageData[34:36]))

		for tagNum := 1; tagNum < firstAvailTag; tagNum++ {
			tagFlags, tagData := db.getTag(pageData, tagNum)
			if tagData == nil || len(tagData) < 10 {
				continue
			}

			// Parse LEAF_ENTRY to get EntryData
			entryData := db.parseLeafEntry(tagData, tagFlags)
			if entryData == nil || len(entryData) < 14 {
				continue
			}

			// Parse catalog entry
			db.parseCatalogEntry(entryData, &datatableTableID)
		}

		// Stop if we have enough columns
		if len(db.columnNameToID) > 1000 {
			break
		}
	}

	return nil
}

// getTag extracts a tag from a page using the correct format
func (db *Database) getTag(pageData []byte, tagNum int) (int, []byte) {
	if len(pageData) < db.headerSize {
		return 0, nil
	}

	firstAvailTag := int(binary.LittleEndian.Uint16(pageData[34:36]))
	if tagNum >= firstAvailTag {
		return 0, nil
	}

	// Tags are at the end of the page, format: [size:2][offset_flags:2]
	cursor := int(db.pageSize) - 4*(tagNum+1)
	if cursor < 0 || cursor+4 > len(pageData) {
		return 0, nil
	}

	word1 := binary.LittleEndian.Uint16(pageData[cursor : cursor+2])
	word2 := binary.LittleEndian.Uint16(pageData[cursor+2 : cursor+4])

	valueSize := int(word1 & 0x1FFF)
	valueOffset := int(word2 & 0x1FFF)
	tagFlags := int((word2 >> 13) & 0x7)

	actualOffset := db.headerSize + valueOffset
	if actualOffset+valueSize > len(pageData) || valueSize == 0 {
		return 0, nil
	}

	return tagFlags, pageData[actualOffset : actualOffset+valueSize]
}

// parseLeafEntry extracts EntryData from a leaf entry
func (db *Database) parseLeafEntry(tagData []byte, tagFlags int) []byte {
	if len(tagData) < 4 {
		return nil
	}

	offset := 0

	// If TAG_COMMON is set, skip CommonPageKeySize (2 bytes)
	if tagFlags&TAG_COMMON != 0 {
		offset += 2
	}

	if offset+2 > len(tagData) {
		return nil
	}

	// LocalPageKeySize (2 bytes)
	localKeySize := int(binary.LittleEndian.Uint16(tagData[offset : offset+2]))
	offset += 2

	// Skip LocalPageKey
	offset += localKeySize

	if offset >= len(tagData) {
		return nil
	}

	return tagData[offset:]
}

// parseCatalogEntry parses a single catalog entry
func (db *Database) parseCatalogEntry(entryData []byte, datatableTableID *uint32) {
	if len(entryData) < 14 {
		return
	}

	// Data Definition Header
	lastFixed := int(entryData[0])
	varOffset := int(binary.LittleEndian.Uint16(entryData[2:4]))

	if lastFixed < 1 || lastFixed > 20 || varOffset < 4 || varOffset > 200 {
		return
	}

	// Fixed data starts at offset 4
	fixedData := entryData[4:]
	if len(fixedData) < 10 {
		return
	}

	fatherID := binary.LittleEndian.Uint32(fixedData[0:4])
	entryType := binary.LittleEndian.Uint16(fixedData[4:6])
	identifier := binary.LittleEndian.Uint32(fixedData[6:10])

	// Get name from variable data
	// Variable columns section format:
	// - Array of 2-byte end offsets (one per variable column)
	// - Actual variable data follows the offset array
	// The name is the first variable column (column ID 128)
	name := ""
	lastVar := int(entryData[1])
	numVarCols := 0
	if lastVar > 127 {
		numVarCols = lastVar - 127
	}

	if numVarCols > 0 && varOffset < len(entryData) {
		varData := entryData[varOffset:]
		offsetArraySize := numVarCols * 2
		if len(varData) >= offsetArraySize+2 {
			// First variable column end offset
			firstEndOffset := int(binary.LittleEndian.Uint16(varData[0:2])) & 0x7FFF
			// Name data starts right after the offset array
			nameStart := offsetArraySize
			nameEnd := offsetArraySize + firstEndOffset
			if nameEnd <= len(varData) && firstEndOffset > 0 {
				name = string(varData[nameStart:nameEnd])
			}
		}
	}

	switch entryType {
	case CATALOG_TYPE_TABLE:
		// Track datatable specially for column mappings
		if name == "datatable" {
			*datatableTableID = identifier
		}
		// Store all tables
		tableDef := &TableDef{
			Name:              name,
			TableID:           identifier,
			FatherDataPageNum: fatherID,
			Columns:           make(map[uint32]*ColumnDef),
			ColumnsByName:     make(map[string]*ColumnDef),
			db:                db,
		}
		db.tables[name] = tableDef

	case CATALOG_TYPE_COLUMN:
		// Store column mapping for datatable
		if *datatableTableID > 0 && fatherID == *datatableTableID {
			db.columnNameToID[name] = identifier
		}

		// Find the parent table and add column to it
		for _, tableDef := range db.tables {
			if tableDef.TableID == fatherID {
				col := &ColumnDef{
					ID:   identifier,
					Name: name,
				}
				if len(fixedData) >= 18 {
					col.Type = binary.LittleEndian.Uint32(fixedData[10:14])
					col.SpaceUsage = binary.LittleEndian.Uint32(fixedData[14:18])
				}
				tableDef.Columns[identifier] = col
				tableDef.ColumnsByName[name] = col
				break
			}
		}

	case CATALOG_TYPE_INDEX:
		// Find the parent table and add index to it
		for _, tableDef := range db.tables {
			if tableDef.TableID == fatherID {
				// Check if index already exists
				found := false
				for _, idx := range db.indexes[tableDef.Name] {
					if idx == name {
						found = true
						break
					}
				}
				if !found {
					db.indexes[tableDef.Name] = append(db.indexes[tableDef.Name], name)
				}
				break
			}
		}
	}
}

// getPageData returns raw page data for a page number
func (db *Database) getPageData(pageNum uint32) []byte {
	offset := uint64(pageNum+1) * uint64(db.pageSize)
	if offset+uint64(db.pageSize) > uint64(len(db.data)) {
		return nil
	}
	return db.data[offset : offset+uint64(db.pageSize)]
}

// GetColumnID returns the ESE column ID for a column name
func (db *Database) GetColumnID(name string) (uint32, bool) {
	id, ok := db.columnNameToID[name]
	return id, ok
}

// GetAllColumnMappings returns all column name to ESE ID mappings
func (db *Database) GetAllColumnMappings() map[string]uint32 {
	result := make(map[string]uint32)
	for name, id := range db.columnNameToID {
		result[name] = id
	}
	return result
}

// OpenTable opens a table for reading records
func (db *Database) OpenTable(name string) (*Table, error) {
	tableDef, ok := db.tables[name]
	if !ok {
		return nil, fmt.Errorf("table not found: %s", name)
	}

	table := &Table{
		def: tableDef,
		db:  db,
	}

	// Scan all leaf pages for records
	table.scanAllPages()

	return table, nil
}

// scanAllPages scans all leaf pages for records
func (t *Table) scanAllPages() {
	numPages := uint32(len(t.db.data)) / t.db.pageSize

	for pageNum := uint32(1); pageNum < numPages; pageNum++ {
		pageData := t.db.getPageData(pageNum)
		if pageData == nil {
			continue
		}

		pageFlags := binary.LittleEndian.Uint32(pageData[36:40])

		// Only process leaf pages, not space tree or index
		if pageFlags&FLAGS_LEAF == 0 || pageFlags&FLAGS_SPACE_TREE != 0 || pageFlags&FLAGS_INDEX != 0 {
			continue
		}

		firstAvailTag := int(binary.LittleEndian.Uint16(pageData[34:36]))

		for tagNum := 1; tagNum < firstAvailTag; tagNum++ {
			tagFlags, tagData := t.db.getTag(pageData, tagNum)
			if tagData == nil || len(tagData) < 4 {
				continue
			}

			entryData := t.db.parseLeafEntry(tagData, tagFlags)
			if entryData == nil || len(entryData) < 4 {
				continue
			}

			record := t.parseRecord(entryData)
			if record != nil && len(record.columns) > 0 {
				t.records = append(t.records, record)
			}
		}
	}
}

// parseRecord parses a record from entry data
func (t *Table) parseRecord(entryData []byte) *Record {
	if len(entryData) < 4 {
		return nil
	}

	record := &Record{
		columns: make(map[string][]byte),
	}

	// Data Definition Header
	lastVar := int(entryData[1])
	varOffset := int(binary.LittleEndian.Uint16(entryData[2:4]))

	if varOffset > len(entryData) {
		return nil
	}

	// Calculate number of variable columns
	numVarCols := 0
	if lastVar > 127 {
		numVarCols = lastVar - 127
	}

	// Calculate end of variable data
	varDataEnd := 0
	if numVarCols > 0 && varOffset+numVarCols*2 <= len(entryData) {
		for i := 0; i < numVarCols; i++ {
			off := varOffset + i*2
			if off+2 > len(entryData) {
				break
			}
			endOff := int(binary.LittleEndian.Uint16(entryData[off : off+2]))
			if endOff&0x8000 == 0 {
				varDataEnd = endOff & 0x7FFF
			}
		}
	}

	// Tagged columns start after variable data
	taggedStart := varOffset + numVarCols*2 + varDataEnd
	if taggedStart >= len(entryData) {
		return record
	}

	// Parse tagged columns
	t.parseTaggedColumns(record, entryData, taggedStart)

	return record
}

// parseTaggedColumns parses tagged columns from record data
func (t *Table) parseTaggedColumns(record *Record, entryData []byte, taggedStart int) {
	taggedData := entryData[taggedStart:]
	if len(taggedData) < 4 {
		return
	}

	// First offset tells us array size
	// Format: [colID:2][offset:2] repeating
	firstOff := int(binary.LittleEndian.Uint16(taggedData[2:4])) & 0x3FFF
	if firstOff == 0 || firstOff > len(taggedData) {
		return
	}

	numEntries := firstOff / 4

	type tagEntry struct {
		id     uint16
		offset uint16
		flags  uint16
	}

	var entries []tagEntry
	for i := 0; i < numEntries && i*4+4 <= len(taggedData); i++ {
		pos := i * 4
		id := binary.LittleEndian.Uint16(taggedData[pos : pos+2])
		offRaw := binary.LittleEndian.Uint16(taggedData[pos+2 : pos+4])
		off := offRaw & 0x3FFF
		flags := offRaw >> 14

		entries = append(entries, tagEntry{id: id, offset: off, flags: flags})
	}

	// Extract data for each tagged column
	for i, entry := range entries {
		var dataLen int
		if i+1 < len(entries) {
			dataLen = int(entries[i+1].offset) - int(entry.offset)
		} else {
			dataLen = len(taggedData) - int(entry.offset)
		}

		if dataLen <= 0 || int(entry.offset)+dataLen > len(taggedData) {
			continue
		}

		colData := taggedData[entry.offset : int(entry.offset)+dataLen]

		// Skip flags byte if present
		if entry.flags&0x1 != 0 && len(colData) > 1 {
			colData = colData[1:]
		}

		// Find column name by ESE ID
		for name, eseID := range t.db.columnNameToID {
			if eseID == uint32(entry.id) {
				record.columns[name] = colData
				break
			}
		}

		// Also store by ID for direct access
		record.columns[fmt.Sprintf("_ID_%d", entry.id)] = colData
	}
}

// NumRecords returns the number of records
func (t *Table) NumRecords() int {
	return len(t.records)
}

// GetRecord retrieves a record by index
func (t *Table) GetRecord(index int) (*Record, error) {
	if index < 0 || index >= len(t.records) {
		return nil, fmt.Errorf("record index out of bounds: %d", index)
	}
	return t.records[index], nil
}

// GetColumn retrieves a column value by name
func (r *Record) GetColumn(name string) []byte {
	return r.columns[name]
}

// GetColumnByID retrieves a column value by ESE column ID
func (r *Record) GetColumnByID(id uint32) []byte {
	return r.columns[fmt.Sprintf("_ID_%d", id)]
}

// GetColumnString retrieves a column as a string (decodes UTF-16LE)
func (r *Record) GetColumnString(name string) string {
	data := r.columns[name]
	if data == nil {
		return ""
	}
	return decodeUTF16(data)
}

// GetAllColumns returns all columns in the record
func (r *Record) GetAllColumns() map[string][]byte {
	return r.columns
}

// decodeUTF16 decodes UTF-16LE bytes to a string
func decodeUTF16(data []byte) string {
	if len(data) < 2 {
		return string(data)
	}

	runes := make([]rune, 0, len(data)/2)
	for i := 0; i+1 < len(data); i += 2 {
		r := rune(uint16(data[i]) | uint16(data[i+1])<<8)
		if r == 0 {
			break
		}
		runes = append(runes, r)
	}
	return string(runes)
}

// GetInfo returns database information
func (db *Database) GetInfo() *DatabaseInfo {
	return &DatabaseInfo{
		Version:        db.version,
		FormatRevision: db.formatRevision,
		PageSize:       db.pageSize,
		NumPages:       uint32(len(db.data)) / db.pageSize,
	}
}

// GetTables returns a list of all table names
func (db *Database) GetTables() []string {
	names := make([]string, 0, len(db.tables))
	for name := range db.tables {
		names = append(names, name)
	}
	return names
}

// GetTableColumns returns column definitions for a table
func (db *Database) GetTableColumns(tableName string) []*ColumnDef {
	tableDef, ok := db.tables[tableName]
	if !ok {
		return nil
	}

	cols := make([]*ColumnDef, 0, len(tableDef.Columns))
	for _, col := range tableDef.Columns {
		cols = append(cols, col)
	}
	return cols
}

// GetTableIndexes returns index names for a table
func (db *Database) GetTableIndexes(tableName string) []string {
	if indexes, ok := db.indexes[tableName]; ok {
		return indexes
	}
	return nil
}

// GetPage returns raw page data for a page number
func (db *Database) GetPage(pageNum int) []byte {
	return db.getPageData(uint32(pageNum))
}

// GetPageInfo returns page header information
func (db *Database) GetPageInfo(pageNum int) *PageInfo {
	pageData := db.getPageData(uint32(pageNum))
	if pageData == nil || len(pageData) < 40 {
		return nil
	}

	// ESENT_PAGE_HEADER (new format):
	// CheckSum (8) | LastModTime (8) | PrevPage (4) | NextPage (4) |
	// FatherDataPage (4) | AvailDataSize (2) | AvailUncommitted (2) |
	// FirstAvailDataOffset (2) | FirstAvailTag (2) | PageFlags (4)
	return &PageInfo{
		PrevPage:      binary.LittleEndian.Uint32(pageData[16:20]),
		NextPage:      binary.LittleEndian.Uint32(pageData[20:24]),
		FirstAvailTag: binary.LittleEndian.Uint16(pageData[34:36]),
		Flags:         binary.LittleEndian.Uint32(pageData[36:40]),
	}
}
