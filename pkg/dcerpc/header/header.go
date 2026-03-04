package header

// RPC Packet Types
const (
	PktTypeRequest  = 0
	PktTypePing     = 1
	PktTypeResponse = 2
	PktTypeFault    = 3
	PktTypeBind     = 11
	PktTypeBindAck  = 12
	PktTypeBindNak  = 13
	PktTypeAlterContext = 14
	PktTypeAlterContextResp = 15
	PktTypeAuth3       = 16
)

// Bind context result codes
const (
	ContResultAccept       = 0
	ContResultProvReject   = 2
	ContResultNegotiateAck = 3
)

// Flags
const (
	FlagFirstFrag  = 0x01
	FlagLastFrag   = 0x02
	FlagObjectUUID = 0x80 // PFC_OBJECT_UUID - request contains object UUID
)

// CommonHeader is the standard header for all connection-oriented RPC packets.
// 16 bytes total.
type CommonHeader struct {
	MajorVersion uint8 // 5
	MinorVersion uint8 // 0
	PacketType   uint8
	PacketFlags  uint8
	DataRep      [4]byte // 0x10000000 for Little Endian
	FragLength   uint16
	AuthLength   uint16
	CallID       uint32
}

// BindHeader specific to Bind requests.
type BindHeader struct {
	MaxXmitFrag  uint16
	MaxRecvFrag  uint16
	AssocGroup   uint32
	// Context List follows
}

// RequestHeader specific to Request packets.
type RequestHeader struct {
	AllocHint uint32
	ContextID uint16
	OpNum     uint16
}

// ContextItem represents an interface to bind to.
type ContextItem struct {
	ContextID      uint16
	NumTransItems  uint8  // Usually 1
	Reserved       uint8
	InterfaceUUID  [16]byte
	InterfaceVer   uint16 // Major
	InterfaceVerMin uint16 // Minor
	TransferSyntax [16]byte // NDR UUID
	TransferVer    uint32
}

// Standard NDR Transfer Syntax UUID (8a885d04-1ceb-11c9-9fe8-08002b104860) v2.0
var TransferSyntaxNDR = [16]byte{
	0x04, 0x5d, 0x88, 0x8a, 0xeb, 0x1c, 0xc9, 0x11,
	0x9f, 0xe8, 0x08, 0x00, 0x2b, 0x10, 0x48, 0x60,
}

// NDR64 Transfer Syntax UUID (71710533-beba-4937-8319-b5dbef9ccc36) v1.0
// Used to detect 64-bit systems - only supported on 64-bit Windows
var TransferSyntaxNDR64 = [16]byte{
	0x33, 0x05, 0x71, 0x71, 0xba, 0xbe, 0x37, 0x49,
	0x83, 0x19, 0xb5, 0xdb, 0xef, 0x9c, 0xcc, 0x36,
}
