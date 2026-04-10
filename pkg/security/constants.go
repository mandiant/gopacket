// SPDX-License-Identifier: Apache-2.0

package security

// ACE Types
const (
	ACCESS_ALLOWED_ACE_TYPE        = 0x00
	ACCESS_DENIED_ACE_TYPE         = 0x01
	SYSTEM_AUDIT_ACE_TYPE          = 0x02
	ACCESS_ALLOWED_OBJECT_ACE_TYPE = 0x05
	ACCESS_DENIED_OBJECT_ACE_TYPE  = 0x06
	SYSTEM_AUDIT_OBJECT_ACE_TYPE   = 0x07
)

// ACE Flags
const (
	OBJECT_INHERIT_ACE         = 0x01
	CONTAINER_INHERIT_ACE      = 0x02
	NO_PROPAGATE_INHERIT_ACE   = 0x04
	INHERIT_ONLY_ACE           = 0x08
	INHERITED_ACE              = 0x10
	SUCCESSFUL_ACCESS_ACE_FLAG = 0x40
	FAILED_ACCESS_ACE_FLAG     = 0x80
)

// Object ACE Flags (in ObjectFlags field)
const (
	ACE_OBJECT_TYPE_PRESENT           = 0x01
	ACE_INHERITED_OBJECT_TYPE_PRESENT = 0x02
)

// Access Mask - Generic Rights
const (
	GENERIC_READ    = 0x80000000
	GENERIC_WRITE   = 0x40000000
	GENERIC_EXECUTE = 0x20000000
	GENERIC_ALL     = 0x10000000
)

// Access Mask - Standard Rights
const (
	DELETE       = 0x00010000
	READ_CONTROL = 0x00020000
	WRITE_DAC    = 0x00040000
	WRITE_OWNER  = 0x00080000
	SYNCHRONIZE  = 0x00100000
)

// Access Mask - Directory Service Rights
const (
	DS_CREATE_CHILD   = 0x00000001
	DS_DELETE_CHILD   = 0x00000002
	DS_LIST_CONTENTS  = 0x00000004
	DS_SELF           = 0x00000008
	DS_READ_PROP      = 0x00000010
	DS_WRITE_PROP     = 0x00000020
	DS_DELETE_TREE    = 0x00000040
	DS_LIST_OBJECT    = 0x00000080
	DS_CONTROL_ACCESS = 0x00000100
)

// Full Control mask for Active Directory objects
const (
	FULL_CONTROL = 0x000F01FF
)

// Security Descriptor Control Flags
const (
	SE_OWNER_DEFAULTED     = 0x0001
	SE_GROUP_DEFAULTED     = 0x0002
	SE_DACL_PRESENT        = 0x0004
	SE_DACL_DEFAULTED      = 0x0008
	SE_SACL_PRESENT        = 0x0010
	SE_SACL_DEFAULTED      = 0x0020
	SE_DACL_AUTO_INHERITED = 0x0400
	SE_SACL_AUTO_INHERITED = 0x0800
	SE_DACL_PROTECTED      = 0x1000
	SE_SACL_PROTECTED      = 0x2000
	SE_SELF_RELATIVE       = 0x8000
)

// DACL_SECURITY_INFORMATION for SD Flags control
const (
	OWNER_SECURITY_INFORMATION = 0x01
	GROUP_SECURITY_INFORMATION = 0x02
	DACL_SECURITY_INFORMATION  = 0x04
	SACL_SECURITY_INFORMATION  = 0x08
)

// Extended Rights GUIDs
var (
	GUID_DS_REPLICATION_GET_CHANGES     GUID
	GUID_DS_REPLICATION_GET_CHANGES_ALL GUID
	GUID_WRITE_MEMBERS                  GUID
	GUID_RESET_PASSWORD                 GUID
)

func init() {
	GUID_DS_REPLICATION_GET_CHANGES, _ = ParseGUID("1131f6aa-9c07-11d1-f79f-00c04fc2dcd2")
	GUID_DS_REPLICATION_GET_CHANGES_ALL, _ = ParseGUID("1131f6ad-9c07-11d1-f79f-00c04fc2dcd2")
	GUID_WRITE_MEMBERS, _ = ParseGUID("bf9679c0-0de6-11d0-a285-00aa003049e2")
	GUID_RESET_PASSWORD, _ = ParseGUID("00299570-246d-11d0-a768-00aa006e0529")
}

// ACE type names for display
var ACETypeNames = map[uint8]string{
	ACCESS_ALLOWED_ACE_TYPE:        "ACCESS_ALLOWED",
	ACCESS_DENIED_ACE_TYPE:         "ACCESS_DENIED",
	SYSTEM_AUDIT_ACE_TYPE:          "SYSTEM_AUDIT",
	ACCESS_ALLOWED_OBJECT_ACE_TYPE: "ACCESS_ALLOWED_OBJECT",
	ACCESS_DENIED_OBJECT_ACE_TYPE:  "ACCESS_DENIED_OBJECT",
	SYSTEM_AUDIT_OBJECT_ACE_TYPE:   "SYSTEM_AUDIT_OBJECT",
}

// Well-known SIDs for display
var WellKnownSIDs = map[string]string{
	"S-1-0-0":      "Nobody",
	"S-1-1-0":      "Everyone",
	"S-1-3-0":      "Creator Owner",
	"S-1-3-1":      "Creator Group",
	"S-1-5-7":      "Anonymous",
	"S-1-5-9":      "Enterprise Domain Controllers",
	"S-1-5-10":     "Principal Self",
	"S-1-5-11":     "Authenticated Users",
	"S-1-5-18":     "Local System",
	"S-1-5-19":     "Local Service",
	"S-1-5-20":     "Network Service",
	"S-1-5-32-544": "Administrators",
	"S-1-5-32-545": "BUILTIN\\Users",
	"S-1-5-32-546": "BUILTIN\\Guests",
	"S-1-5-32-547": "BUILTIN\\Power Users",
	"S-1-5-32-548": "BUILTIN\\Account Operators",
	"S-1-5-32-549": "BUILTIN\\Server Operators",
	"S-1-5-32-550": "BUILTIN\\Print Operators",
	"S-1-5-32-551": "BUILTIN\\Backup Operators",
	"S-1-5-32-552": "BUILTIN\\Replicators",
	"S-1-5-32-554": "BUILTIN\\Pre-Windows 2000 Compatible Access",
	"S-1-5-32-555": "BUILTIN\\Remote Desktop Users",
	"S-1-5-32-556": "BUILTIN\\Network Configuration Operators",
	"S-1-5-32-557": "BUILTIN\\Incoming Forest Trust Builders",
	"S-1-5-32-558": "BUILTIN\\Performance Monitor Users",
	"S-1-5-32-559": "BUILTIN\\Performance Log Users",
	"S-1-5-32-560": "BUILTIN\\Windows Authorization Access Group",
	"S-1-5-32-561": "BUILTIN\\Terminal Server License Servers",
	"S-1-5-32-562": "BUILTIN\\Distributed COM Users",
	"S-1-5-32-568": "BUILTIN\\IIS_IUSRS",
	"S-1-5-32-569": "BUILTIN\\Cryptographic Operators",
	"S-1-5-32-573": "BUILTIN\\Event Log Readers",
	"S-1-5-32-574": "BUILTIN\\Certificate Service DCOM Access",
	"S-1-5-32-575": "BUILTIN\\RDS Remote Access Servers",
	"S-1-5-32-576": "BUILTIN\\RDS Endpoint Servers",
	"S-1-5-32-577": "BUILTIN\\RDS Management Servers",
	"S-1-5-32-578": "BUILTIN\\Hyper-V Administrators",
	"S-1-5-32-579": "BUILTIN\\Access Control Assistance Operators",
	"S-1-5-32-580": "BUILTIN\\Remote Management Users",
}

// Well-known domain-relative RIDs for display
var WellKnownRIDs = map[uint32]string{
	500: "Administrator",
	501: "Guest",
	502: "krbtgt",
	512: "Domain Admins",
	513: "Domain Users",
	514: "Domain Guests",
	515: "Domain Computers",
	516: "Domain Controllers",
	517: "Cert Publishers",
	518: "Schema Admins",
	519: "Enterprise Admins",
	520: "Group Policy Creator Owners",
	521: "Read-only Domain Controllers",
	522: "Cloneable Domain Controllers",
	525: "Protected Users",
	526: "Key Admins",
	527: "Enterprise Key Admins",
	553: "RAS and IAS Servers",
	571: "Allowed RODC Password Replication Group",
	572: "Denied RODC Password Replication Group",
}

// Well-known GUIDs for display: extended rights, property sets, schema classes and attributes
var ExtendedRightsGUIDs = map[string]string{
	// Extended Rights
	"1131f6aa-9c07-11d1-f79f-00c04fc2dcd2": "DS-Replication-Get-Changes",
	"1131f6ad-9c07-11d1-f79f-00c04fc2dcd2": "DS-Replication-Get-Changes-All",
	"1131f6ab-9c07-11d1-f79f-00c04fc2dcd2": "DS-Replication-Get-Changes-In-Filtered-Set",
	"00299570-246d-11d0-a768-00aa006e0529": "User-Force-Change-Password",
	"ab721a53-1e2f-11d0-9819-00aa0040529b": "User-Change-Password",
	"00000000-0000-0000-0000-000000000000": "All Extended Rights",
	"89e95b76-444d-4c62-991a-0facbeda640c": "DS-Replication-Get-Changes-In-Filtered-Set",
	"ccc2dc7d-a6ad-4a7a-8846-c04e3cc53501": "Unexpire-Password",
	"280f369c-67c7-438e-ae98-1d46f3c6f541": "Update-Password-Not-Required-Bit",
	"be2bb760-7f46-11d2-b9ad-00c04f79f805": "Update-Schema-Cache",
	"ab721a54-1e2f-11d0-9819-00aa0040529b": "Send-As",
	"ab721a56-1e2f-11d0-9819-00aa0040529b": "Receive-As",
	"9923a32a-3607-11d2-b9be-0000f87a36b2": "DS-Install-Replica",
	"cc17b1fb-33d9-11d2-97d4-00c04fd8d5cd": "DS-Query-Self-Quota",

	// Property Sets
	"4c164200-20c0-11d0-a768-00aa006e0529": "User-Account-Restrictions",
	"5f202010-79a5-11d0-9020-00c04fc2d4cf": "User-Logon",
	"bc0ac240-79a9-11d0-9020-00c04fc2d4cf": "Membership",
	"59ba2f42-79a2-11d0-9020-00c04fc2d3cf": "General-Information",
	"037088f8-0ae1-11d2-b422-00a0c968f939": "RAS-Information",
	"ffa6f046-ca4b-4feb-b40d-04dfee722543": "MS-TS-GatewayAccess",
	"5805bc62-bdc9-4428-a5e2-856a0f4c185e": "Terminal-Server",
	"77b5b886-944a-11d1-aebd-0000f80367c1": "Personal-Information",
	"91e647de-d96f-4b70-9557-d63ff4f3ccd8": "Private-Information",
	"e45795b2-9455-11d1-aebd-0000f80367c1": "Email-Information",
	"e45795b3-9455-11d1-aebd-0000f80367c1": "Web-Information",
	"b8119fd0-04f6-4762-ab7a-4986c76b3f9a": "Domain-Other-Parameters",
	"c7407360-20bf-11d0-a768-00aa006e0529": "Domain-Password",
	"e48d0154-bcf8-11d1-8702-00c04fb96050": "Public-Information",
	"72e39547-7b18-11d1-adef-00c04fd8d5cd": "DNS-Host-Name-Attributes",
	"b7c69e6d-2cc7-11d2-854e-00a0c983f608": "Validated-DNS-Host-Name",
	"80863791-dbe9-4eb8-837e-7f0ab55d9ac7": "Validated-MS-DS-Additional-DNS-Host-Name",
	"d31a8757-2447-4545-8081-3bb610cacbf2": "Validated-MS-DS-Behavior-Version",
	"f3a64788-5306-11d1-a9c5-0000f80367c1": "Validated-SPN",

	// Schema Classes
	"4828cc14-1437-45bc-9b07-ad6f015e5f28": "inetOrgPerson",
	"bf967aba-0de6-11d0-a285-00aa003049e2": "User",
	"bf967a86-0de6-11d0-a285-00aa003049e2": "Computer",
	"bf967a9c-0de6-11d0-a285-00aa003049e2": "Group",
	"bf967aa5-0de6-11d0-a285-00aa003049e2": "Organizational-Unit",
	"19195a5b-6da0-11d0-afd3-00c04fd930c9": "Domain",
	"f0f8ffab-1191-11d0-a060-00aa006c33ed": "Trusted-Domain",
	"bf967a7f-0de6-11d0-a285-00aa003049e2": "X509-Cert",
	"ce206244-5827-4a86-ba1c-1c0c386c1b64": "ms-DS-Key-Credential-Link",

	// Schema Attributes
	"bf9679c0-0de6-11d0-a285-00aa003049e2": "Self-Membership",
	"46a9b11d-60ae-405a-b7e8-ff8a58d456d2": "Token-Groups-Global-And-Universal",
	"6db69a1c-9422-11d1-aebd-0000f80367c1": "Terminal-Server-License-Server",
	"5b47d60f-6090-40b2-9f37-2a4de88f3063": "ms-DS-Key-Credential-Link (attr)",
	"bf967950-0de6-11d0-a285-00aa003049e2": "Description",
	"bf967953-0de6-11d0-a285-00aa003049e2": "Display-Name",
	"28630ebe-41d5-11d1-a9c1-0000f80367c1": "GP-Link",
	"f30e3bbe-9ff0-11d1-b603-0000f80367c1": "GP-Options",
	"bf9679a8-0de6-11d0-a285-00aa003049e2": "GP-Options (attr)",
}
