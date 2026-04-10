// SPDX-License-Identifier: Apache-2.0

package security

import (
	"fmt"
	"strings"
)

// FormatACE returns a human-readable representation of an ACE.
func FormatACE(ace *ACE, resolveSID func(*SID) string) string {
	typeName := ACETypeNames[ace.Type]
	if typeName == "" {
		typeName = fmt.Sprintf("UNKNOWN(0x%02x)", ace.Type)
	}

	sidStr := ace.SID.String()
	principal := sidStr
	if resolveSID != nil {
		if name := resolveSID(ace.SID); name != "" {
			principal = name
			// Ensure SID is always shown in parentheses
			if !strings.Contains(name, sidStr) {
				principal = fmt.Sprintf("%s (%s)", name, sidStr)
			}
		}
	}

	maskStr := FormatAccessMask(ace.Mask)

	var parts []string
	parts = append(parts, fmt.Sprintf("  Type: %s", typeName))
	parts = append(parts, fmt.Sprintf("  Principal: %s", principal))
	parts = append(parts, fmt.Sprintf("  Access Mask: 0x%08x (%s)", ace.Mask, maskStr))

	if ace.Flags != 0 {
		parts = append(parts, fmt.Sprintf("  ACE Flags: 0x%02x (%s)", ace.Flags, FormatACEFlags(ace.Flags)))
	}

	if ace.IsObjectACE() {
		if !ace.ObjectType.IsZero() {
			guidName := GUIDToName(ace.ObjectType)
			parts = append(parts, fmt.Sprintf("  Object Type: %s (%s)", ace.ObjectType.String(), guidName))
		}
		if !ace.InheritedObjectType.IsZero() {
			guidName := GUIDToName(ace.InheritedObjectType)
			parts = append(parts, fmt.Sprintf("  Inherited Object Type: %s (%s)", ace.InheritedObjectType.String(), guidName))
		}
	}

	return strings.Join(parts, "\n")
}

// FormatAccessMask decomposes an access mask into named flags.
func FormatAccessMask(mask uint32) string {
	var flags []string

	if mask == FULL_CONTROL {
		return "FULL_CONTROL"
	}
	if mask&GENERIC_ALL != 0 {
		flags = append(flags, "GENERIC_ALL")
		mask &^= GENERIC_ALL
	}
	if mask&GENERIC_READ != 0 {
		flags = append(flags, "GENERIC_READ")
		mask &^= GENERIC_READ
	}
	if mask&GENERIC_WRITE != 0 {
		flags = append(flags, "GENERIC_WRITE")
		mask &^= GENERIC_WRITE
	}
	if mask&GENERIC_EXECUTE != 0 {
		flags = append(flags, "GENERIC_EXECUTE")
		mask &^= GENERIC_EXECUTE
	}
	if mask&WRITE_OWNER != 0 {
		flags = append(flags, "WRITE_OWNER")
		mask &^= WRITE_OWNER
	}
	if mask&WRITE_DAC != 0 {
		flags = append(flags, "WRITE_DAC")
		mask &^= WRITE_DAC
	}
	if mask&READ_CONTROL != 0 {
		flags = append(flags, "READ_CONTROL")
		mask &^= READ_CONTROL
	}
	if mask&DELETE != 0 {
		flags = append(flags, "DELETE")
		mask &^= DELETE
	}
	if mask&SYNCHRONIZE != 0 {
		flags = append(flags, "SYNCHRONIZE")
		mask &^= SYNCHRONIZE
	}
	if mask&DS_CONTROL_ACCESS != 0 {
		flags = append(flags, "DS_CONTROL_ACCESS")
		mask &^= DS_CONTROL_ACCESS
	}
	if mask&DS_WRITE_PROP != 0 {
		flags = append(flags, "DS_WRITE_PROP")
		mask &^= DS_WRITE_PROP
	}
	if mask&DS_READ_PROP != 0 {
		flags = append(flags, "DS_READ_PROP")
		mask &^= DS_READ_PROP
	}
	if mask&DS_SELF != 0 {
		flags = append(flags, "DS_SELF")
		mask &^= DS_SELF
	}
	if mask&DS_LIST_CONTENTS != 0 {
		flags = append(flags, "DS_LIST_CONTENTS")
		mask &^= DS_LIST_CONTENTS
	}
	if mask&DS_DELETE_CHILD != 0 {
		flags = append(flags, "DS_DELETE_CHILD")
		mask &^= DS_DELETE_CHILD
	}
	if mask&DS_CREATE_CHILD != 0 {
		flags = append(flags, "DS_CREATE_CHILD")
		mask &^= DS_CREATE_CHILD
	}
	if mask&DS_DELETE_TREE != 0 {
		flags = append(flags, "DS_DELETE_TREE")
		mask &^= DS_DELETE_TREE
	}
	if mask&DS_LIST_OBJECT != 0 {
		flags = append(flags, "DS_LIST_OBJECT")
		mask &^= DS_LIST_OBJECT
	}

	if mask != 0 {
		flags = append(flags, fmt.Sprintf("0x%x", mask))
	}

	if len(flags) == 0 {
		return "NONE"
	}
	return strings.Join(flags, "|")
}

// FormatACEFlags formats ACE flags as a string.
func FormatACEFlags(flags uint8) string {
	var names []string
	if flags&OBJECT_INHERIT_ACE != 0 {
		names = append(names, "OBJECT_INHERIT")
	}
	if flags&CONTAINER_INHERIT_ACE != 0 {
		names = append(names, "CONTAINER_INHERIT")
	}
	if flags&NO_PROPAGATE_INHERIT_ACE != 0 {
		names = append(names, "NO_PROPAGATE_INHERIT")
	}
	if flags&INHERIT_ONLY_ACE != 0 {
		names = append(names, "INHERIT_ONLY")
	}
	if flags&INHERITED_ACE != 0 {
		names = append(names, "INHERITED")
	}
	if len(names) == 0 {
		return "NONE"
	}
	return strings.Join(names, "|")
}

// GUIDToName looks up a GUID in the extended rights table.
func GUIDToName(g GUID) string {
	if name, ok := ExtendedRightsGUIDs[g.String()]; ok {
		return name
	}
	return "Unknown"
}
