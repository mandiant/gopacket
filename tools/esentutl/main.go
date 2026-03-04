package main

import (
	"encoding/hex"
	"flag"
	"fmt"
	"log"
	"os"
	"sort"
	"strings"

	"gopacket/internal/build"
	"gopacket/pkg/ese"
)

var (
	debug    = flag.Bool("debug", false, "Turn DEBUG output ON")
	ts       = flag.Bool("ts", false, "Adds timestamp to every logging output")
	pageNum  = flag.Int("page", -1, "page to dump (for dump action)")
	table    = flag.String("table", "", "table to export (for export action)")
)

func init() {
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, `esentutl - Extensive Storage Engine utility

Allows dumping catalog, pages and tables from ESE databases (like ntds.dit).

Usage: esentutl [options] <databaseFile> <action>

Actions:
  info    - Dumps the catalog info for the DB (tables, columns, indexes)
  dump    - Dumps a specific page (requires -page)
  export  - Exports a table's records (requires -table)

Examples:
  esentutl ntds.dit info
  esentutl ntds.dit dump -page 4
  esentutl ntds.dit export -table datatable

Options:
`)
		flag.PrintDefaults()
	}
}

func main() {
	// Custom argument parsing to match Impacket's syntax:
	// esentutl <databaseFile> <action> [flags]
	// Go's flag package requires flags before positional args, but
	// Impacket uses: esentutl ntds.dit dump -page 4

	args := os.Args[1:]
	if len(args) < 2 {
		flag.Usage()
		os.Exit(1)
	}

	// Extract database file and action before flags
	databaseFile := args[0]
	action := strings.ToLower(args[1])

	// Parse remaining args as flags
	if len(args) > 2 {
		flag.CommandLine.Parse(args[2:])
	}

	if *debug {
		build.Debug = true
	}

	// Read database file
	data, err := os.ReadFile(databaseFile)
	if err != nil {
		log.Fatalf("[-] Failed to read database file: %v", err)
	}

	fmt.Printf("[*] Opening database: %s (%d bytes)\n", databaseFile, len(data))

	db, err := ese.Open(data)
	if err != nil {
		log.Fatalf("[-] Failed to open ESE database: %v", err)
	}

	switch action {
	case "info":
		doInfo(db)
	case "dump":
		if *pageNum < 0 {
			log.Fatal("[-] -page is required for dump action")
		}
		doDump(db, *pageNum)
	case "export":
		if *table == "" {
			log.Fatal("[-] -table is required for export action")
		}
		doExport(db, *table)
	default:
		log.Fatalf("[-] Unknown action: %s", action)
	}
}

func doInfo(db *ese.Database) {
	info := db.GetInfo()

	fmt.Printf("Database version: 0x%x, 0x%x\n", info.Version, info.FormatRevision)
	fmt.Printf("Page size: %d\n", info.PageSize)
	fmt.Printf("Number of pages: %d\n", info.NumPages)
	fmt.Println()

	fmt.Println("Catalog:")
	tables := db.GetTables()
	sort.Strings(tables)
	for _, tableName := range tables {
		fmt.Printf("[%s]\n", tableName)

		columns := db.GetTableColumns(tableName)
		if len(columns) > 0 {
			// Sort columns by ID
			sort.Slice(columns, func(i, j int) bool {
				return columns[i].ID < columns[j].ID
			})
			fmt.Println("    Columns")
			for _, col := range columns {
				fmt.Printf("        %-5d %-30s %s\n", col.ID, col.Name, ese.ColumnTypeName(col.Type))
			}
		}

		indexes := db.GetTableIndexes(tableName)
		if len(indexes) > 0 {
			fmt.Println("    Indexes")
			for _, idx := range indexes {
				fmt.Printf("        %s\n", idx)
			}
		}
		fmt.Println()
	}
}

func doDump(db *ese.Database, pageNum int) {
	fmt.Printf("[*] Dumping page %d\n\n", pageNum)

	pageData := db.GetPage(pageNum)
	if pageData == nil {
		log.Fatalf("[-] Failed to get page %d", pageNum)
	}

	// Print page header info
	pageInfo := db.GetPageInfo(pageNum)
	if pageInfo != nil {
		fmt.Printf("Page Flags: 0x%04x", pageInfo.Flags)
		var flagNames []string
		if pageInfo.Flags&ese.FLAGS_ROOT != 0 {
			flagNames = append(flagNames, "ROOT")
		}
		if pageInfo.Flags&ese.FLAGS_LEAF != 0 {
			flagNames = append(flagNames, "LEAF")
		}
		if pageInfo.Flags&ese.FLAGS_PARENT != 0 {
			flagNames = append(flagNames, "PARENT")
		}
		if pageInfo.Flags&ese.FLAGS_EMPTY != 0 {
			flagNames = append(flagNames, "EMPTY")
		}
		if pageInfo.Flags&ese.FLAGS_SPACE_TREE != 0 {
			flagNames = append(flagNames, "SPACE_TREE")
		}
		if pageInfo.Flags&ese.FLAGS_INDEX != 0 {
			flagNames = append(flagNames, "INDEX")
		}
		if pageInfo.Flags&ese.FLAGS_LONG_VALUE != 0 {
			flagNames = append(flagNames, "LONG_VALUE")
		}
		if pageInfo.Flags&ese.FLAGS_NEW_CHECKSUM != 0 {
			flagNames = append(flagNames, "NEW_CHECKSUM")
		}
		if pageInfo.Flags&ese.FLAGS_NEW_FORMAT != 0 {
			flagNames = append(flagNames, "NEW_FORMAT")
		}
		if len(flagNames) > 0 {
			fmt.Printf(" (%s)", strings.Join(flagNames, ", "))
		}
		fmt.Println()
		fmt.Printf("Previous Page: %d\n", pageInfo.PrevPage)
		fmt.Printf("Next Page: %d\n", pageInfo.NextPage)
		fmt.Printf("First Available Tag: %d\n", pageInfo.FirstAvailTag)
		fmt.Println()
	}

	// Hex dump of page data
	fmt.Println("Page Data:")
	hexDump(pageData)
}

func doExport(db *ese.Database, tableName string) {
	fmt.Printf("[*] Exporting table: %s\n\n", tableName)

	table, err := db.OpenTable(tableName)
	if err != nil {
		log.Fatalf("[-] Failed to open table: %v", err)
	}

	numRecords := table.NumRecords()
	fmt.Printf("Table: %s (%d records)\n\n", tableName, numRecords)

	for i := 0; i < numRecords; i++ {
		record, err := table.GetRecord(i)
		if err != nil {
			continue
		}

		fmt.Printf("*** %d\n", i+1)
		columns := record.GetAllColumns()
		for name, data := range columns {
			if data != nil && len(data) > 0 {
				// Skip internal ID columns for cleaner output
				if strings.HasPrefix(name, "_ID_") {
					continue
				}
				fmt.Printf("%-30s: %s\n", name, formatValue(data))
			}
		}
		fmt.Println()
	}
}

// formatValue formats a column value for display
func formatValue(data []byte) string {
	if len(data) == 0 {
		return "<empty>"
	}

	// Try to detect if it's printable text
	printable := true
	for _, b := range data {
		if b < 32 && b != 0 && b != '\t' && b != '\n' && b != '\r' {
			printable = false
			break
		}
	}

	// Check for UTF-16LE (common in ESE)
	if len(data) >= 2 && len(data)%2 == 0 {
		isUTF16 := true
		hasNullTerminator := false
		for i := 0; i < len(data); i += 2 {
			if data[i] == 0 && i+1 < len(data) && data[i+1] == 0 {
				hasNullTerminator = true
				break
			}
			if i+1 < len(data) && data[i+1] != 0 && data[i+1] > 0x7F {
				isUTF16 = false
				break
			}
		}
		if isUTF16 && (hasNullTerminator || isPrintableUTF16(data)) {
			return decodeUTF16(data)
		}
	}

	if printable && len(data) < 200 {
		s := string(data)
		s = strings.TrimRight(s, "\x00")
		if len(s) > 0 {
			return s
		}
	}

	// Return hex for binary data
	if len(data) > 64 {
		return fmt.Sprintf("0x%s... (%d bytes)", hex.EncodeToString(data[:64]), len(data))
	}
	return fmt.Sprintf("0x%s", hex.EncodeToString(data))
}

func isPrintableUTF16(data []byte) bool {
	for i := 0; i < len(data); i += 2 {
		if i+1 >= len(data) {
			break
		}
		ch := uint16(data[i]) | uint16(data[i+1])<<8
		if ch == 0 {
			return true // null terminator
		}
		if ch < 32 && ch != '\t' && ch != '\n' && ch != '\r' {
			return false
		}
	}
	return true
}

func decodeUTF16(data []byte) string {
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

func hexDump(data []byte) {
	for i := 0; i < len(data); i += 16 {
		// Offset
		fmt.Printf("%08x  ", i)

		// Hex bytes
		for j := 0; j < 16; j++ {
			if i+j < len(data) {
				fmt.Printf("%02x ", data[i+j])
			} else {
				fmt.Print("   ")
			}
			if j == 7 {
				fmt.Print(" ")
			}
		}

		// ASCII
		fmt.Print(" |")
		for j := 0; j < 16 && i+j < len(data); j++ {
			b := data[i+j]
			if b >= 32 && b <= 126 {
				fmt.Printf("%c", b)
			} else {
				fmt.Print(".")
			}
		}
		fmt.Println("|")
	}
}
