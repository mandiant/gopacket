// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jacob Paullus

package ntfs

import (
	"encoding/binary"
	"fmt"
	"io"
	"os"
	"strings"
	"time"
)

// Attribute types
const (
	AttrStandardInformation = 0x10
	AttrAttributeList       = 0x20
	AttrFileName            = 0x30
	AttrObjectID            = 0x40
	AttrSecurityDescriptor  = 0x50
	AttrVolumeName          = 0x60
	AttrVolumeInformation   = 0x70
	AttrData                = 0x80
	AttrIndexRoot           = 0x90
	AttrIndexAllocation     = 0xA0
	AttrBitmap              = 0xB0
	AttrEnd                 = 0xFFFFFFFF
)

// File attribute flags
const (
	FileAttrReadOnly        = 0x0001
	FileAttrHidden          = 0x0002
	FileAttrSystem          = 0x0004
	FileAttrDirectory       = 0x0010
	FileAttrArchive         = 0x0020
	FileAttrCompressed      = 0x0800
	FileAttrEncrypted       = 0x4000
	FileAttrSparse          = 0x0200
	FileAttrI30IndexPresent = 0x10000000
)

// File name types
const (
	FileNamePOSIX       = 0x00
	FileNameWin32       = 0x01
	FileNameDOS         = 0x02
	FileNameWin32AndDOS = 0x03
)

// Index entry flags
const (
	IndexEntryNode = 1
	IndexEntryEnd  = 2
)

// System MFT numbers
const (
	FileMFT   = 0
	FileRoot  = 5
	FixedMFTs = 16
)

// Windows epoch
var windowsEpoch = time.Date(1601, 1, 1, 0, 0, 0, 0, time.UTC)

// FileTimeToTime converts a Windows FILETIME to Go time.Time
func FileTimeToTime(ft uint64) time.Time {
	if ft == 0 {
		return time.Time{}
	}
	// FILETIME is 100-nanosecond intervals since Jan 1, 1601
	// Convert to Unix time to avoid int64 overflow in time.Duration
	const windowsToUnixEpoch = 116444736000000000
	if ft < windowsToUnixEpoch {
		return time.Time{}
	}
	unixFT := ft - windowsToUnixEpoch
	sec := int64(unixFT / 10000000)
	nsec := int64(unixFT%10000000) * 100
	return time.Unix(sec, nsec)
}

// DataRun represents a single NTFS data run
type DataRun struct {
	LCN      int64
	Clusters uint64
	StartVCN uint64
	LastVCN  uint64
}

// Attribute represents a parsed MFT attribute
type Attribute struct {
	Type        uint32
	Length      uint32
	NonResident bool
	Name        string
	Flags       uint16
	// Resident
	Value []byte
	// Non-resident
	DataRuns  []DataRun
	DataSize  uint64
	AllocSize uint64
	InitSize  uint64
}

// FileEntry represents a file/directory found during directory walking
type FileEntry struct {
	Name           string
	INodeNumber    uint64
	FileAttributes uint32
	DataSize       uint64
	LastModified   time.Time
}

// INode represents a parsed MFT record
type INode struct {
	Volume         *Volume
	INodeNumber    uint64
	FileAttributes uint32
	FileName       string
	FileSize       uint64
	LastModified   time.Time
	Attributes     []Attribute
	rawAttrs       []byte
}

// IsDirectory returns whether this inode is a directory
func (n *INode) IsDirectory() bool {
	return n.FileAttributes&FileAttrI30IndexPresent != 0
}

// IsCompressed returns whether this inode is compressed
func (n *INode) IsCompressed() bool {
	return n.FileAttributes&FileAttrCompressed != 0
}

// IsEncrypted returns whether this inode is encrypted
func (n *INode) IsEncrypted() bool {
	return n.FileAttributes&FileAttrEncrypted != 0
}

// IsSparse returns whether this inode is sparse
func (n *INode) IsSparse() bool {
	return n.FileAttributes&FileAttrSparse != 0
}

// PrintableAttributes returns a 6-char attribute mask string
func (n *INode) PrintableAttributes() string {
	return printableAttrs(n.FileAttributes)
}

func printableAttrs(fa uint32) string {
	mask := [6]byte{'-', '-', '-', '-', '-', '-'}
	if fa&FileAttrI30IndexPresent != 0 {
		mask[0] = 'd'
	}
	if fa&FileAttrHidden != 0 {
		mask[1] = 'h'
	}
	if fa&FileAttrSystem != 0 {
		mask[2] = 'S'
	}
	if fa&FileAttrCompressed != 0 {
		mask[3] = 'C'
	}
	if fa&FileAttrEncrypted != 0 {
		mask[4] = 'E'
	}
	if fa&FileAttrSparse != 0 {
		mask[5] = 's'
	}
	return string(mask[:])
}

// Volume represents an NTFS volume
type Volume struct {
	fd                *os.File
	BytesPerSector    uint16
	SectorsPerCluster uint8
	MFTStart          int64
	RecordSize        int64
	IndexBlockSize    int64
	SectorSize        int64
	mftINode          *INode
}

// Open opens an NTFS volume or image file for reading
func Open(path string) (*Volume, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open volume: %v", err)
	}

	v := &Volume{fd: f}
	if err := v.readBootSector(); err != nil {
		f.Close()
		return nil, err
	}

	// Read MFT inode to check for fragmented MFT
	mftINode, err := v.GetINode(FileMFT)
	if err != nil {
		f.Close()
		return nil, fmt.Errorf("read MFT inode: %v", err)
	}

	for i := range mftINode.Attributes {
		if mftINode.Attributes[i].Type == AttrData && mftINode.Attributes[i].NonResident {
			v.mftINode = mftINode
			break
		}
	}

	return v, nil
}

// Close closes the volume
func (v *Volume) Close() error {
	return v.fd.Close()
}

func (v *Volume) readBootSector() error {
	v.fd.Seek(0, io.SeekStart)
	buf := make([]byte, 512)
	if _, err := io.ReadFull(v.fd, buf); err != nil {
		return fmt.Errorf("read boot sector: %v", err)
	}

	// BPB at offset 11 (after 3-byte jump + 8-byte OEM ID)
	bpb := buf[11:]
	v.BytesPerSector = binary.LittleEndian.Uint16(bpb[0:2])
	v.SectorsPerCluster = bpb[2]
	v.SectorSize = int64(v.BytesPerSector)

	// Extended BPB at offset 36
	// Layout: Reserved(4) + TotalSectors(8) + MFTCluster(8) + MFTMirr(8) +
	//         ClusterPerFileRecord(1) + Reserved(3) + ClusterPerIndexBuffer(1) + Reserved(3) + ...
	ebpb := buf[36:]
	mftCluster := binary.LittleEndian.Uint64(ebpb[12:20])
	clusterPerRecord := int8(ebpb[28])
	clusterPerIndex := int8(ebpb[32])

	clusterSize := int64(v.BytesPerSector) * int64(v.SectorsPerCluster)
	v.MFTStart = int64(mftCluster) * clusterSize

	if clusterPerRecord > 0 {
		v.RecordSize = clusterSize * int64(clusterPerRecord)
	} else {
		v.RecordSize = 1 << uint(-clusterPerRecord)
	}

	if clusterPerIndex > 0 {
		v.IndexBlockSize = clusterSize * int64(clusterPerIndex)
	} else {
		v.IndexBlockSize = 1 << uint(-clusterPerIndex)
	}

	return nil
}

// GetINode reads and parses an MFT record by inode number
func (v *Volume) GetINode(iNodeNum uint64) (*INode, error) {
	var record []byte

	if v.mftINode != nil && iNodeNum > FixedMFTs {
		// Read from fragmented MFT via its DATA attribute
		dataAttr := v.mftINode.findDataAttribute("")
		if dataAttr == nil {
			return nil, fmt.Errorf("no DATA attribute in MFT inode")
		}
		record = v.readNonResident(dataAttr, int64(iNodeNum)*v.RecordSize, v.RecordSize)
	} else {
		pos := v.MFTStart + int64(iNodeNum)*v.RecordSize
		v.fd.Seek(pos, io.SeekStart)
		record = make([]byte, v.RecordSize)
		if _, err := io.ReadFull(v.fd, record); err != nil {
			return nil, fmt.Errorf("read MFT record %d: %v", iNodeNum, err)
		}
	}

	if len(record) < 42 {
		return nil, fmt.Errorf("MFT record too short")
	}

	if string(record[:4]) != "FILE" {
		return nil, fmt.Errorf("invalid MFT record magic: %q", record[:4])
	}

	usrOffset := binary.LittleEndian.Uint16(record[4:6])
	usrSize := binary.LittleEndian.Uint16(record[6:8])
	attrsOffset := binary.LittleEndian.Uint16(record[20:22])

	record = performFixup(record, usrOffset, usrSize, int(v.SectorSize))
	if record == nil {
		return nil, fmt.Errorf("fixup failed for inode %d", iNodeNum)
	}

	inode := &INode{
		Volume:      v,
		INodeNumber: iNodeNum,
		rawAttrs:    record[attrsOffset:],
	}

	inode.parseAttributes()
	return inode, nil
}

// performFixup applies Update Sequence Record fixups
func performFixup(record []byte, usrOffset, usrSize uint16, sectorSize int) []byte {
	if int(usrOffset)+2 > len(record) {
		return nil
	}

	magicNum := binary.LittleEndian.Uint16(record[usrOffset:])
	seqArray := record[usrOffset+2:]

	result := make([]byte, len(record))
	copy(result, record)

	index := 0
	for i := 0; i < int(usrSize-1)*2; i += 2 {
		index += sectorSize - 2
		if index+2 > len(result) {
			break
		}
		lastBytes := binary.LittleEndian.Uint16(result[index:])
		if lastBytes != magicNum {
			return nil
		}
		if i+1 < len(seqArray) {
			result[index] = seqArray[i]
			result[index+1] = seqArray[i+1]
		}
		index += 2
	}

	return result
}

func (n *INode) parseAttributes() {
	// Parse standard information
	data := n.rawAttrs
	for {
		attr := parseAttributeAt(data)
		if attr == nil || attr.Type == AttrEnd {
			break
		}
		if attr.Type == AttrStandardInformation && !attr.NonResident && len(attr.Value) >= 36 {
			n.FileAttributes |= binary.LittleEndian.Uint32(attr.Value[32:36])
			if len(attr.Value) >= 16 {
				n.LastModified = FileTimeToTime(binary.LittleEndian.Uint64(attr.Value[8:16]))
			}
		}
		if attr.Length == 0 {
			break
		}
		data = data[attr.Length:]
	}

	// Parse file name (prefer non-DOS)
	data = n.rawAttrs
	for {
		attr := parseAttributeAt(data)
		if attr == nil || attr.Type == AttrEnd {
			break
		}
		if attr.Type == AttrFileName && !attr.NonResident && len(attr.Value) >= 66 {
			nameType := attr.Value[65]
			if nameType != FileNameDOS {
				nameLen := attr.Value[64]
				if 66+int(nameLen)*2 <= len(attr.Value) {
					n.FileName = decodeUTF16LE(attr.Value[66 : 66+int(nameLen)*2])
					n.FileSize = binary.LittleEndian.Uint64(attr.Value[48:56])
					n.FileAttributes |= binary.LittleEndian.Uint32(attr.Value[56:60])
				}
				break
			}
		}
		if attr.Length == 0 {
			break
		}
		data = data[attr.Length:]
	}

	// Collect all attributes
	data = n.rawAttrs
	n.Attributes = nil
	for {
		attr := parseAttributeAt(data)
		if attr == nil || attr.Type == AttrEnd {
			break
		}
		n.Attributes = append(n.Attributes, *attr)
		if attr.Length == 0 {
			break
		}
		data = data[attr.Length:]
	}
}

func parseAttributeAt(data []byte) *Attribute {
	if len(data) < 16 {
		return nil
	}

	attrType := binary.LittleEndian.Uint32(data[0:4])
	if attrType == AttrEnd || attrType == 0 {
		return &Attribute{Type: AttrEnd}
	}

	attrLen := binary.LittleEndian.Uint32(data[4:8])
	if attrLen == 0 || int(attrLen) > len(data) {
		return &Attribute{Type: AttrEnd}
	}

	nonResident := data[8] != 0
	nameLen := data[9]
	nameOffset := binary.LittleEndian.Uint16(data[10:12])
	flags := binary.LittleEndian.Uint16(data[12:14])

	attr := &Attribute{
		Type:        attrType,
		Length:      attrLen,
		NonResident: nonResident,
		Flags:       flags,
	}

	if nameLen > 0 && int(nameOffset)+int(nameLen)*2 <= len(data) {
		attr.Name = decodeUTF16LE(data[nameOffset : nameOffset+uint16(nameLen)*2])
	}

	if nonResident {
		if len(data) < 64 {
			return attr
		}
		runsOffset := binary.LittleEndian.Uint16(data[32:34])
		attr.AllocSize = binary.LittleEndian.Uint64(data[40:48])
		attr.DataSize = binary.LittleEndian.Uint64(data[48:56])
		attr.InitSize = binary.LittleEndian.Uint64(data[56:64])
		if int(runsOffset) < int(attrLen) {
			attr.DataRuns = parseDataRuns(data[runsOffset:attrLen])
		}
	} else {
		if len(data) < 24 {
			return attr
		}
		valueLen := binary.LittleEndian.Uint32(data[16:20])
		valueOffset := binary.LittleEndian.Uint16(data[20:22])
		if int(valueOffset)+int(valueLen) <= int(attrLen) && int(valueOffset)+int(valueLen) <= len(data) {
			attr.Value = make([]byte, valueLen)
			copy(attr.Value, data[valueOffset:int(valueOffset)+int(valueLen)])
		}
	}

	return attr
}

func parseDataRuns(data []byte) []DataRun {
	var runs []DataRun
	var vcn uint64
	var lcn int64

	for len(data) > 0 && data[0] != 0 {
		size := data[0]
		data = data[1:]

		lengthBytes := int(size & 0x0F)
		offsetBytes := int(size >> 4)

		if lengthBytes == 0 || len(data) < lengthBytes+offsetBytes {
			break
		}

		// Read cluster count (unsigned)
		buf := make([]byte, 8)
		copy(buf, data[:lengthBytes])
		length := binary.LittleEndian.Uint64(buf)
		data = data[lengthBytes:]

		// Read LCN offset (signed, relative to previous)
		var offset int64
		if offsetBytes > 0 {
			buf = make([]byte, 8)
			if data[offsetBytes-1]&0x80 != 0 {
				for i := range buf {
					buf[i] = 0xFF
				}
			}
			copy(buf, data[:offsetBytes])
			offset = int64(binary.LittleEndian.Uint64(buf))
			data = data[offsetBytes:]
		}

		lcn += offset

		run := DataRun{
			LCN:      lcn,
			Clusters: length,
			StartVCN: vcn,
			LastVCN:  vcn + length - 1,
		}
		runs = append(runs, run)
		vcn += length
	}

	return runs
}

func (n *INode) findDataAttribute(name string) *Attribute {
	for i := range n.Attributes {
		if n.Attributes[i].Type == AttrData && n.Attributes[i].Name == name {
			return &n.Attributes[i]
		}
	}
	return nil
}

// readNonResident reads data from a non-resident attribute's data runs
func (v *Volume) readNonResident(attr *Attribute, offset, length int64) []byte {
	clusterSize := int64(v.BytesPerSector) * int64(v.SectorsPerCluster)
	buf := make([]byte, 0, length)
	remaining := length
	curOffset := offset

	for remaining > 0 {
		vcn := curOffset / clusterSize
		found := false

		for _, run := range attr.DataRuns {
			if uint64(vcn) >= run.StartVCN && uint64(vcn) <= run.LastVCN {
				runOffset := vcn - int64(run.StartVCN)
				diskPos := (run.LCN + runOffset) * clusterSize
				offsetInCluster := curOffset % clusterSize
				diskPos += offsetInCluster

				clustersLeft := int64(run.LastVCN) - vcn + 1
				bytesAvail := clustersLeft*clusterSize - offsetInCluster
				if bytesAvail > remaining {
					bytesAvail = remaining
				}

				chunk := make([]byte, bytesAvail)
				v.fd.Seek(diskPos, io.SeekStart)
				n, _ := io.ReadFull(v.fd, chunk)
				buf = append(buf, chunk[:n]...)
				remaining -= int64(n)
				curOffset += int64(n)
				found = true
				break
			}
		}

		if !found {
			break
		}
	}

	return buf
}

// ReadFile reads the entire default data stream of an inode
func (n *INode) ReadFile() ([]byte, error) {
	attr := n.findDataAttribute("")
	if attr == nil {
		return nil, fmt.Errorf("no DATA attribute")
	}
	if !attr.NonResident {
		return attr.Value, nil
	}
	data := n.Volume.readNonResident(attr, 0, int64(attr.DataSize))
	return data, nil
}

// ReadFileChunk reads a chunk of the default data stream
func (n *INode) ReadFileChunk(offset, length int64) ([]byte, error) {
	attr := n.findDataAttribute("")
	if attr == nil {
		return nil, fmt.Errorf("no DATA attribute")
	}
	if !attr.NonResident {
		end := offset + length
		if end > int64(len(attr.Value)) {
			end = int64(len(attr.Value))
		}
		if offset >= int64(len(attr.Value)) {
			return nil, nil
		}
		return attr.Value[offset:end], nil
	}
	data := n.Volume.readNonResident(attr, offset, length)
	return data, nil
}

// GetDataSize returns the size of the default data stream
func (n *INode) GetDataSize() uint64 {
	attr := n.findDataAttribute("")
	if attr == nil {
		return 0
	}
	if !attr.NonResident {
		return uint64(len(attr.Value))
	}
	return attr.DataSize
}

// Walk returns all file/directory entries in this directory
func (n *INode) Walk() ([]FileEntry, error) {
	if !n.IsDirectory() {
		return nil, fmt.Errorf("not a directory")
	}

	var indexRoot *Attribute
	var indexAlloc *Attribute
	for i := range n.Attributes {
		if n.Attributes[i].Type == AttrIndexRoot && n.Attributes[i].Name == "$I30" {
			indexRoot = &n.Attributes[i]
		}
		if n.Attributes[i].Type == AttrIndexAllocation && n.Attributes[i].Name == "$I30" {
			indexAlloc = &n.Attributes[i]
		}
	}

	if indexRoot == nil {
		return nil, fmt.Errorf("no INDEX_ROOT attribute")
	}

	if len(indexRoot.Value) < 32 {
		return nil, fmt.Errorf("INDEX_ROOT too short")
	}

	// INDEX_ROOT: Type(4) + CollationRule(4) + IndexBlockSize(4) + ClustersPerIndexBlock(1) + Reserved(3)
	// INDEX_HEADER: EntriesOffset(4) + IndexLength(4) + AllocatedSize(4) + Flags(1) + Reserved(3)
	entriesOffset := binary.LittleEndian.Uint32(indexRoot.Value[16:20])

	data := indexRoot.Value[16+entriesOffset:]
	entries := n.parseIndexEntries(data, indexAlloc)

	return entries, nil
}

func (n *INode) parseIndexEntries(data []byte, indexAlloc *Attribute) []FileEntry {
	var entries []FileEntry

	for len(data) >= 16 {
		indexedFile := binary.LittleEndian.Uint64(data[0:8])
		entryLen := binary.LittleEndian.Uint16(data[8:10])
		keyLen := binary.LittleEndian.Uint16(data[10:12])
		flags := binary.LittleEndian.Uint16(data[12:14])

		if entryLen == 0 {
			break
		}

		// Sub-node pointer
		if flags&IndexEntryNode != 0 && indexAlloc != nil {
			if int(entryLen) <= len(data) && entryLen >= 8 {
				vcn := binary.LittleEndian.Uint64(data[entryLen-8:])
				subEntries := n.walkSubNodes(int64(vcn), indexAlloc)
				entries = append(entries, subEntries...)
			}
		}

		// Parse the key (FILE_NAME attribute)
		if keyLen > 0 && int(16+keyLen) <= len(data) {
			key := data[16 : 16+keyLen]
			iNodeNum := indexedFile & 0x0000FFFFFFFFFFFF

			if iNodeNum > FixedMFTs && len(key) >= 66 {
				nameType := key[65]
				if nameType != FileNameDOS {
					nameLen := key[64]
					if 66+int(nameLen)*2 <= len(key) {
						entry := FileEntry{
							INodeNumber:    iNodeNum,
							Name:           decodeUTF16LE(key[66 : 66+int(nameLen)*2]),
							FileAttributes: binary.LittleEndian.Uint32(key[56:60]),
							DataSize:       binary.LittleEndian.Uint64(key[48:56]),
							LastModified:   FileTimeToTime(binary.LittleEndian.Uint64(key[16:24])),
						}
						entries = append(entries, entry)
					}
				}
			}
		}

		if flags&IndexEntryEnd != 0 {
			break
		}

		if int(entryLen) > len(data) {
			break
		}
		data = data[entryLen:]
	}

	return entries
}

func (n *INode) walkSubNodes(vcn int64, indexAlloc *Attribute) []FileEntry {
	if indexAlloc == nil || !indexAlloc.NonResident {
		return nil
	}

	data := n.Volume.readNonResident(indexAlloc, vcn*n.Volume.IndexBlockSize, n.Volume.IndexBlockSize)
	if len(data) < 28 {
		return nil
	}

	if string(data[:4]) != "INDX" {
		return nil
	}

	usrOffset := binary.LittleEndian.Uint16(data[4:6])
	usrSize := binary.LittleEndian.Uint16(data[6:8])
	data = performFixup(data, usrOffset, usrSize, int(n.Volume.SectorSize))
	if data == nil {
		return nil
	}

	// INDEX_HEADER at offset 24 (after magic(4)+USR(4)+LSN(8)+IndexVCN(8))
	if len(data) < 40 {
		return nil
	}
	entriesOffset := binary.LittleEndian.Uint32(data[24:28])

	entryData := data[24+entriesOffset:]
	return n.parseIndexEntries(entryData, indexAlloc)
}

// FindFirst searches for a file by name in this directory
func (n *INode) FindFirst(fileName string) *FileEntry {
	entries, err := n.Walk()
	if err != nil {
		return nil
	}

	upper := strings.ToUpper(fileName)
	for _, entry := range entries {
		if strings.ToUpper(entry.Name) == upper {
			return &entry
		}
	}
	return nil
}

// PrintableAttrs returns the attribute mask for a FileEntry
func (e *FileEntry) PrintableAttrs() string {
	return printableAttrs(e.FileAttributes)
}

func decodeUTF16LE(data []byte) string {
	if len(data)%2 != 0 {
		data = data[:len(data)-1]
	}
	runes := make([]rune, len(data)/2)
	for i := 0; i < len(data); i += 2 {
		runes[i/2] = rune(data[i]) | rune(data[i+1])<<8
	}
	return string(runes)
}
