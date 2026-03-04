package header

// Auth Constants
const (
	// AuthnLevel
	AuthnLevelNone          = 0
	AuthnLevelConnect       = 2
	AuthnLevelPkt           = 4
	AuthnLevelPktIntegrity  = 5
	AuthnLevelPktPrivacy    = 6 // Encryption
	
	// AuthnSvc
	AuthnWinNT        = 10 // NTLM
	AuthnGSSNegotiate = 9  // SPNEGO
	AuthnKerberos     = 16
	AuthnNetlogon     = 68
)

// SecTrailer is appended to the body if AuthLength > 0.
type SecTrailer struct {
	AuthType   uint8
	AuthLevel  uint8
	PadLen     uint8
	Reserved   uint8
	ContextID  uint32
}
