package ldap

import (
	"fmt"

	ber "github.com/go-asn1-ber/asn1-ber"
	goldap "github.com/go-ldap/ldap/v3"
)

// ControlMicrosoftSDFlags implements the Microsoft SD Flags control (OID 1.2.840.113556.1.4.801).
// This control specifies which portions of the security descriptor to retrieve or modify.
type ControlMicrosoftSDFlags struct {
	Flags int
}

func (c *ControlMicrosoftSDFlags) GetControlType() string {
	return "1.2.840.113556.1.4.801"
}

func (c *ControlMicrosoftSDFlags) Encode() *ber.Packet {
	packet := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "Control")
	packet.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, c.GetControlType(), "Control Type OID"))
	packet.AppendChild(ber.NewBoolean(ber.ClassUniversal, ber.TypePrimitive, ber.TagBoolean, true, "Criticality"))

	// The control value is: SEQUENCE { INTEGER flags }
	// BER-encode the sequence, then wrap as OCTET STRING raw bytes
	seq := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "SD Flags Value")
	seq.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagInteger, int64(c.Flags), "Flags"))

	packet.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, string(seq.Bytes()), "Control Value"))

	return packet
}

func (c *ControlMicrosoftSDFlags) String() string {
	return fmt.Sprintf("Control Type: %s  Criticality: true  Flags: %d", c.GetControlType(), c.Flags)
}

// NewControlMicrosoftSDFlags creates a new SD Flags control.
// Common flag values: 0x04 = DACL_SECURITY_INFORMATION
func NewControlMicrosoftSDFlags(flags int) *ControlMicrosoftSDFlags {
	return &ControlMicrosoftSDFlags{Flags: flags}
}

// ModifyChange represents a single modification to an LDAP entry.
type ModifyChange struct {
	Operation int      // goldap.AddAttribute, ReplaceAttribute, DeleteAttribute
	AttrName  string
	AttrVals  []string
}

// Add creates a new LDAP entry with the given DN and attributes.
func (c *Client) Add(dn string, attributes map[string][]string) error {
	if c.Conn == nil {
		return fmt.Errorf("connection not established")
	}

	addReq := goldap.NewAddRequest(dn, nil)
	for name, vals := range attributes {
		addReq.Attribute(name, vals)
	}

	return c.Conn.Add(addReq)
}

// Modify applies changes to an existing LDAP entry.
func (c *Client) Modify(dn string, changes []ModifyChange) error {
	if c.Conn == nil {
		return fmt.Errorf("connection not established")
	}

	modReq := goldap.NewModifyRequest(dn, nil)
	for _, ch := range changes {
		switch ch.Operation {
		case goldap.AddAttribute:
			modReq.Add(ch.AttrName, ch.AttrVals)
		case goldap.ReplaceAttribute:
			modReq.Replace(ch.AttrName, ch.AttrVals)
		case goldap.DeleteAttribute:
			modReq.Delete(ch.AttrName, ch.AttrVals)
		}
	}

	return c.Conn.Modify(modReq)
}

// ModifyRequest performs an LDAP modify with a pre-built ModifyRequest.
// This allows for complex modifications like delete+add in the same request.
func (c *Client) ModifyRequest(modReq *goldap.ModifyRequest) error {
	if c.Conn == nil {
		return fmt.Errorf("connection not established")
	}
	return c.Conn.Modify(modReq)
}

// Delete removes an LDAP entry by its DN.
func (c *Client) Delete(dn string) error {
	if c.Conn == nil {
		return fmt.Errorf("connection not established")
	}

	delReq := goldap.NewDelRequest(dn, nil)
	return c.Conn.Del(delReq)
}

// ModifyRaw performs an LDAP modify with raw byte values and optional controls.
// This is needed for writing binary attributes like nTSecurityDescriptor.
func (c *Client) ModifyRaw(dn string, operation int, attrName string, rawValue []byte, controls []goldap.Control) error {
	if c.Conn == nil {
		return fmt.Errorf("connection not established")
	}

	modReq := goldap.NewModifyRequest(dn, controls)
	// go-ldap accepts string values which are transmitted as OCTET STRING on the wire
	switch operation {
	case goldap.AddAttribute:
		modReq.Add(attrName, []string{string(rawValue)})
	case goldap.ReplaceAttribute:
		modReq.Replace(attrName, []string{string(rawValue)})
	case goldap.DeleteAttribute:
		modReq.Delete(attrName, []string{string(rawValue)})
	default:
		return fmt.Errorf("unsupported LDAP operation: %d", operation)
	}

	return c.Conn.Modify(modReq)
}
