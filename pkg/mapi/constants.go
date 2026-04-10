// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jacob Paullus

// Package mapi provides MAPI (Messaging Application Programming Interface)
// constants and helpers for working with Exchange address book properties.
// This is a modular library that can be used by multiple tools.
package mapi

// MAPI Error Codes
const (
	MAPI_E_INTERFACE_NO_SUPPORT        = 0x80004002
	MAPI_E_CALL_FAILED                 = 0x80004005
	MAPI_E_NO_SUPPORT                  = 0x80040102
	MAPI_E_BAD_CHARWIDTH               = 0x80040103
	MAPI_E_STRING_TOO_LONG             = 0x80040105
	MAPI_E_UNKNOWN_FLAGS               = 0x80040106
	MAPI_E_INVALID_ENTRYID             = 0x80040107
	MAPI_E_INVALID_OBJECT              = 0x80040108
	MAPI_E_OBJECT_CHANGED              = 0x80040109
	MAPI_E_OBJECT_DELETED              = 0x8004010A
	MAPI_E_BUSY                        = 0x8004010B
	MAPI_E_NOT_ENOUGH_DISK             = 0x8004010D
	MAPI_E_NOT_ENOUGH_RESOURCES        = 0x8004010E
	MAPI_E_NOT_FOUND                   = 0x8004010F
	MAPI_E_VERSION                     = 0x80040110
	MAPI_E_LOGON_FAILED                = 0x80040111
	MAPI_E_SESSION_LIMIT               = 0x80040112
	MAPI_E_USER_CANCEL                 = 0x80040113
	MAPI_E_UNABLE_TO_ABORT             = 0x80040114
	MAPI_E_NETWORK_ERROR               = 0x80040115
	MAPI_E_DISK_ERROR                  = 0x80040116
	MAPI_E_TOO_COMPLEX                 = 0x80040117
	MAPI_E_BAD_COLUMN                  = 0x80040118
	MAPI_E_EXTENDED_ERROR              = 0x80040119
	MAPI_E_COMPUTED                    = 0x8004011A
	MAPI_E_CORRUPT_DATA                = 0x8004011B
	MAPI_E_UNCONFIGURED                = 0x8004011C
	MAPI_E_FAILONEPROVIDER             = 0x8004011D
	MAPI_E_UNKNOWN_CPID                = 0x8004011E
	MAPI_E_UNKNOWN_LCID                = 0x8004011F
	MAPI_E_PASSWORD_CHANGE_REQUIRED    = 0x80040120
	MAPI_E_PASSWORD_EXPIRED            = 0x80040121
	MAPI_E_INVALID_WORKSTATION_ACCOUNT = 0x80040122
	MAPI_E_INVALID_ACCESS_TIME         = 0x80040123
	MAPI_E_ACCOUNT_DISABLED            = 0x80040124
	MAPI_E_END_OF_SESSION              = 0x80040200
	MAPI_E_UNKNOWN_ENTRYID             = 0x80040201
	MAPI_E_MISSING_REQUIRED_COLUMN     = 0x80040202
	MAPI_W_NO_SERVICE                  = 0x00040203
	MAPI_E_BAD_VALUE                   = 0x80040301
	MAPI_E_INVALID_TYPE                = 0x80040302
	MAPI_E_TYPE_NO_SUPPORT             = 0x80040303
	MAPI_E_UNEXPECTED_TYPE             = 0x80040304
	MAPI_E_TOO_BIG                     = 0x80040305
	MAPI_E_DECLINE_COPY                = 0x80040306
	MAPI_E_UNEXPECTED_ID               = 0x80040307
	MAPI_W_ERRORS_RETURNED             = 0x00040380
	MAPI_E_UNABLE_TO_COMPLETE          = 0x80040400
	MAPI_E_TIMEOUT                     = 0x80040401
	MAPI_E_TABLE_EMPTY                 = 0x80040402
	MAPI_E_TABLE_TOO_BIG               = 0x80040403
	MAPI_E_INVALID_BOOKMARK            = 0x80040405
	MAPI_W_POSITION_CHANGED            = 0x00040481
	MAPI_W_APPROX_COUNT                = 0x00040482
	MAPI_E_WAIT                        = 0x80040500
	MAPI_E_CANCEL                      = 0x80040501
	MAPI_E_NOT_ME                      = 0x80040502
	MAPI_W_CANCEL_MESSAGE              = 0x00040580
	MAPI_E_CORRUPT_STORE               = 0x80040600
	MAPI_E_NOT_IN_QUEUE                = 0x80040601
	MAPI_E_NO_SUPPRESS                 = 0x80040602
	MAPI_E_COLLISION                   = 0x80040604
	MAPI_E_NOT_INITIALIZED             = 0x80040605
	MAPI_E_NON_STANDARD                = 0x80040606
	MAPI_E_NO_RECIPIENTS               = 0x80040607
	MAPI_E_SUBMITTED                   = 0x80040608
	MAPI_E_HAS_FOLDERS                 = 0x80040609
	MAPI_E_HAS_MESAGES                 = 0x8004060A
	MAPI_E_FOLDER_CYCLE                = 0x8004060B
	MAPI_E_LOCKID_LIMIT                = 0x8004060D
	MAPI_W_PARTIAL_COMPLETION          = 0x00040680
	MAPI_E_AMBIGUOUS_RECIP             = 0x80040700
	MAPI_E_NAMED_PROP_QUOTA_EXCEEDED   = 0x80040900
	MAPI_E_NOT_IMPLEMENTED             = 0x80040FFF
	MAPI_E_NO_ACCESS                   = 0x80070005
	MAPI_E_NOT_ENOUGH_MEMORY           = 0x8007000E
	MAPI_E_INVALID_PARAMETER           = 0x80070057

	LDAP_NO_SUCH_OBJECT = 0x80040920
	LDAP_SERVER_DOWN    = 0x80040951
	LDAP_LOCAL_ERROR    = 0x80040952
)

// ErrorMessages maps error codes to human-readable messages
var ErrorMessages = map[uint32]string{
	MAPI_E_INTERFACE_NO_SUPPORT:        "MAPI_E_INTERFACE_NO_SUPPORT",
	MAPI_E_CALL_FAILED:                 "MAPI_E_CALL_FAILED",
	MAPI_E_NO_SUPPORT:                  "MAPI_E_NO_SUPPORT",
	MAPI_E_BAD_CHARWIDTH:               "MAPI_E_BAD_CHARWIDTH",
	MAPI_E_STRING_TOO_LONG:             "MAPI_E_STRING_TOO_LONG",
	MAPI_E_UNKNOWN_FLAGS:               "MAPI_E_UNKNOWN_FLAGS",
	MAPI_E_INVALID_ENTRYID:             "MAPI_E_INVALID_ENTRYID",
	MAPI_E_INVALID_OBJECT:              "MAPI_E_INVALID_OBJECT",
	MAPI_E_OBJECT_CHANGED:              "MAPI_E_OBJECT_CHANGED",
	MAPI_E_OBJECT_DELETED:              "MAPI_E_OBJECT_DELETED",
	MAPI_E_BUSY:                        "MAPI_E_BUSY",
	MAPI_E_NOT_ENOUGH_DISK:             "MAPI_E_NOT_ENOUGH_DISK",
	MAPI_E_NOT_ENOUGH_RESOURCES:        "MAPI_E_NOT_ENOUGH_RESOURCES",
	MAPI_E_NOT_FOUND:                   "MAPI_E_NOT_FOUND",
	MAPI_E_VERSION:                     "MAPI_E_VERSION",
	MAPI_E_LOGON_FAILED:                "MAPI_E_LOGON_FAILED",
	MAPI_E_SESSION_LIMIT:               "MAPI_E_SESSION_LIMIT",
	MAPI_E_USER_CANCEL:                 "MAPI_E_USER_CANCEL",
	MAPI_E_UNABLE_TO_ABORT:             "MAPI_E_UNABLE_TO_ABORT",
	MAPI_E_NETWORK_ERROR:               "MAPI_E_NETWORK_ERROR",
	MAPI_E_DISK_ERROR:                  "MAPI_E_DISK_ERROR",
	MAPI_E_TOO_COMPLEX:                 "MAPI_E_TOO_COMPLEX",
	MAPI_E_BAD_COLUMN:                  "MAPI_E_BAD_COLUMN",
	MAPI_E_EXTENDED_ERROR:              "MAPI_E_EXTENDED_ERROR",
	MAPI_E_COMPUTED:                    "MAPI_E_COMPUTED",
	MAPI_E_CORRUPT_DATA:                "MAPI_E_CORRUPT_DATA",
	MAPI_E_UNCONFIGURED:                "MAPI_E_UNCONFIGURED",
	MAPI_E_FAILONEPROVIDER:             "MAPI_E_FAILONEPROVIDER",
	MAPI_E_UNKNOWN_CPID:                "MAPI_E_UNKNOWN_CPID",
	MAPI_E_UNKNOWN_LCID:                "MAPI_E_UNKNOWN_LCID",
	MAPI_E_PASSWORD_CHANGE_REQUIRED:    "MAPI_E_PASSWORD_CHANGE_REQUIRED",
	MAPI_E_PASSWORD_EXPIRED:            "MAPI_E_PASSWORD_EXPIRED",
	MAPI_E_INVALID_WORKSTATION_ACCOUNT: "MAPI_E_INVALID_WORKSTATION_ACCOUNT",
	MAPI_E_INVALID_ACCESS_TIME:         "MAPI_E_INVALID_ACCESS_TIME",
	MAPI_E_ACCOUNT_DISABLED:            "MAPI_E_ACCOUNT_DISABLED",
	MAPI_E_END_OF_SESSION:              "MAPI_E_END_OF_SESSION",
	MAPI_E_UNKNOWN_ENTRYID:             "MAPI_E_UNKNOWN_ENTRYID",
	MAPI_E_MISSING_REQUIRED_COLUMN:     "MAPI_E_MISSING_REQUIRED_COLUMN",
	MAPI_W_NO_SERVICE:                  "MAPI_W_NO_SERVICE",
	MAPI_E_BAD_VALUE:                   "MAPI_E_BAD_VALUE",
	MAPI_E_INVALID_TYPE:                "MAPI_E_INVALID_TYPE",
	MAPI_E_TYPE_NO_SUPPORT:             "MAPI_E_TYPE_NO_SUPPORT",
	MAPI_E_UNEXPECTED_TYPE:             "MAPI_E_UNEXPECTED_TYPE",
	MAPI_E_TOO_BIG:                     "MAPI_E_TOO_BIG",
	MAPI_E_DECLINE_COPY:                "MAPI_E_DECLINE_COPY",
	MAPI_E_UNEXPECTED_ID:               "MAPI_E_UNEXPECTED_ID",
	MAPI_W_ERRORS_RETURNED:             "MAPI_W_ERRORS_RETURNED",
	MAPI_E_UNABLE_TO_COMPLETE:          "MAPI_E_UNABLE_TO_COMPLETE",
	MAPI_E_TIMEOUT:                     "MAPI_E_TIMEOUT",
	MAPI_E_TABLE_EMPTY:                 "MAPI_E_TABLE_EMPTY",
	MAPI_E_TABLE_TOO_BIG:               "MAPI_E_TABLE_TOO_BIG",
	MAPI_E_INVALID_BOOKMARK:            "MAPI_E_INVALID_BOOKMARK",
	MAPI_W_POSITION_CHANGED:            "MAPI_W_POSITION_CHANGED",
	MAPI_W_APPROX_COUNT:                "MAPI_W_APPROX_COUNT",
	MAPI_E_WAIT:                        "MAPI_E_WAIT",
	MAPI_E_CANCEL:                      "MAPI_E_CANCEL",
	MAPI_E_NOT_ME:                      "MAPI_E_NOT_ME",
	MAPI_W_CANCEL_MESSAGE:              "MAPI_W_CANCEL_MESSAGE",
	MAPI_E_CORRUPT_STORE:               "MAPI_E_CORRUPT_STORE",
	MAPI_E_NOT_IN_QUEUE:                "MAPI_E_NOT_IN_QUEUE",
	MAPI_E_NO_SUPPRESS:                 "MAPI_E_NO_SUPPRESS",
	MAPI_E_COLLISION:                   "MAPI_E_COLLISION",
	MAPI_E_NOT_INITIALIZED:             "MAPI_E_NOT_INITIALIZED",
	MAPI_E_NON_STANDARD:                "MAPI_E_NON_STANDARD",
	MAPI_E_NO_RECIPIENTS:               "MAPI_E_NO_RECIPIENTS",
	MAPI_E_SUBMITTED:                   "MAPI_E_SUBMITTED",
	MAPI_E_HAS_FOLDERS:                 "MAPI_E_HAS_FOLDERS",
	MAPI_E_HAS_MESAGES:                 "MAPI_E_HAS_MESAGES",
	MAPI_E_FOLDER_CYCLE:                "MAPI_E_FOLDER_CYCLE",
	MAPI_E_LOCKID_LIMIT:                "MAPI_E_LOCKID_LIMIT",
	MAPI_W_PARTIAL_COMPLETION:          "MAPI_W_PARTIAL_COMPLETION",
	MAPI_E_AMBIGUOUS_RECIP:             "MAPI_E_AMBIGUOUS_RECIP",
	MAPI_E_NAMED_PROP_QUOTA_EXCEEDED:   "MAPI_E_NAMED_PROP_QUOTA_EXCEEDED",
	MAPI_E_NOT_IMPLEMENTED:             "MAPI_E_NOT_IMPLEMENTED",
	MAPI_E_NO_ACCESS:                   "MAPI_E_NO_ACCESS",
	MAPI_E_NOT_ENOUGH_MEMORY:           "MAPI_E_NOT_ENOUGH_MEMORY",
	MAPI_E_INVALID_PARAMETER:           "MAPI_E_INVALID_PARAMETER",
	LDAP_NO_SUCH_OBJECT:                "LDAP_NO_SUCH_OBJECT",
	LDAP_SERVER_DOWN:                   "LDAP_SERVER_DOWN",
	LDAP_LOCAL_ERROR:                   "LDAP_LOCAL_ERROR",
}

// PR_DISPLAY_TYPE values (for address book contents tables)
const (
	DT_MAILUSER         = 0x00000000
	DT_DISTLIST         = 0x00000001
	DT_FORUM            = 0x00000002
	DT_AGENT            = 0x00000003
	DT_ORGANIZATION     = 0x00000004
	DT_PRIVATE_DISTLIST = 0x00000005
	DT_REMOTE_MAILUSER  = 0x00000006
	// For address book hierarchy tables
	DT_MODIFIABLE   = 0x00010000
	DT_GLOBAL       = 0x00020000
	DT_LOCAL        = 0x00030000
	DT_WAN          = 0x00040000
	DT_NOT_SPECIFIC = 0x00050000
	// For folder hierarchy tables
	DT_FOLDER         = 0x01000000
	DT_FOLDER_LINK    = 0x02000000
	DT_FOLDER_SPECIAL = 0x04000000
)

// DisplayTypeValues maps display type values to names
var DisplayTypeValues = map[uint32]string{
	DT_MAILUSER:         "DT_MAILUSER",
	DT_DISTLIST:         "DT_DISTLIST",
	DT_FORUM:            "DT_FORUM",
	DT_AGENT:            "DT_AGENT",
	DT_ORGANIZATION:     "DT_ORGANIZATION",
	DT_PRIVATE_DISTLIST: "DT_PRIVATE_DISTLIST",
	DT_REMOTE_MAILUSER:  "DT_REMOTE_MAILUSER",
	DT_MODIFIABLE:       "DT_MODIFIABLE",
	DT_GLOBAL:           "DT_GLOBAL",
	DT_LOCAL:            "DT_LOCAL",
	DT_WAN:              "DT_WAN",
	DT_NOT_SPECIFIC:     "DT_NOT_SPECIFIC",
	DT_FOLDER:           "DT_FOLDER",
	DT_FOLDER_LINK:      "DT_FOLDER_LINK",
	DT_FOLDER_SPECIAL:   "DT_FOLDER_SPECIAL",
}

// PR_OBJECT_TYPE values
const (
	MAPI_STORE    = 0x1
	MAPI_ADDRBOOK = 0x2
	MAPI_FOLDER   = 0x3
	MAPI_ABCONT   = 0x4
	MAPI_MESSAGE  = 0x5
	MAPI_MAILUSER = 0x6
	MAPI_ATTACH   = 0x7
	MAPI_DISTLIST = 0x8
	MAPI_PROFSECT = 0x9
	MAPI_STATUS   = 0xA
	MAPI_SESSION  = 0xB
	MAPI_FORMINFO = 0xC
)

// ObjectTypeValues maps object type values to names
var ObjectTypeValues = map[uint32]string{
	MAPI_STORE:    "MAPI_STORE",
	MAPI_ADDRBOOK: "MAPI_ADDRBOOK",
	MAPI_FOLDER:   "MAPI_FOLDER",
	MAPI_ABCONT:   "MAPI_ABCONT",
	MAPI_MESSAGE:  "MAPI_MESSAGE",
	MAPI_MAILUSER: "MAPI_MAILUSER",
	MAPI_ATTACH:   "MAPI_ATTACH",
	MAPI_DISTLIST: "MAPI_DISTLIST",
	MAPI_PROFSECT: "MAPI_PROFSECT",
	MAPI_STATUS:   "MAPI_STATUS",
	MAPI_SESSION:  "MAPI_SESSION",
	MAPI_FORMINFO: "MAPI_FORMINFO",
}

// PR_CONTAINER_FLAGS values
const (
	AB_RECIPIENTS    = 0x00000001
	AB_SUBCONTAINERS = 0x00000002
	AB_MODIFIABLE    = 0x00000004
	AB_UNMODIFIABLE  = 0x00000008
	AB_FIND_ON_OPEN  = 0x00000010
	AB_NOT_DEFAULT   = 0x00000020
	AB_CONF_ROOMS    = 0x00000200
)

// ContainerFlagsValues maps container flag values to names
var ContainerFlagsValues = map[uint32]string{
	AB_RECIPIENTS:    "AB_RECIPIENTS",
	AB_SUBCONTAINERS: "AB_SUBCONTAINERS",
	AB_MODIFIABLE:    "AB_MODIFIABLE",
	AB_UNMODIFIABLE:  "AB_UNMODIFIABLE",
	AB_FIND_ON_OPEN:  "AB_FIND_ON_OPEN",
	AB_NOT_DEFAULT:   "AB_NOT_DEFAULT",
	AB_CONF_ROOMS:    "AB_CONF_ROOMS",
}

// Property Tags used by exchanger
const (
	PR_CONTAINER_FLAGS       = 0x36000003
	PR_ENTRYID               = 0x0fff0102
	PR_DEPTH                 = 0x30050003
	PR_EMS_AB_IS_MASTER      = 0xfffb000B
	PR_EMS_AB_CONTAINERID    = 0xfffd0003
	PR_EMS_AB_PARENT_ENTRYID = 0xfffc0102
	PR_DISPLAY_NAME          = 0x3001001F
	PR_EMS_AB_OBJECT_GUID    = 0x8c6d0102
	PR_INSTANCE_KEY          = 0x0ff60102
	PR_OBJECT_TYPE           = 0x0ffe0003
	PR_DISPLAY_TYPE          = 0x39000003
)

// Property types
const (
	PT_UNSPECIFIED  = 0x0000
	PT_NULL         = 0x0001
	PT_I2           = 0x0002 // 16-bit signed int
	PT_LONG         = 0x0003 // 32-bit signed int
	PT_R4           = 0x0004 // 32-bit float
	PT_DOUBLE       = 0x0005 // 64-bit float
	PT_CURRENCY     = 0x0006
	PT_APPTIME      = 0x0007
	PT_ERROR        = 0x000A
	PT_BOOLEAN      = 0x000B
	PT_OBJECT       = 0x000D // Embedded object
	PT_I8           = 0x0014 // 64-bit signed int
	PT_STRING8      = 0x001E // ANSI string
	PT_UNICODE      = 0x001F // Unicode string
	PT_SYSTIME      = 0x0040 // FILETIME
	PT_CLSID        = 0x0048
	PT_SVREID       = 0x00FB
	PT_SRESTRICTION = 0x00FD
	PT_ACTIONS      = 0x00FE
	PT_BINARY       = 0x0102
	PT_MV_I2        = 0x1002
	PT_MV_LONG      = 0x1003
	PT_MV_R4        = 0x1004
	PT_MV_DOUBLE    = 0x1005
	PT_MV_CURRENCY  = 0x1006
	PT_MV_APPTIME   = 0x1007
	PT_MV_I8        = 0x1014
	PT_MV_STRING8   = 0x101E
	PT_MV_UNICODE   = 0x101F
	PT_MV_SYSTIME   = 0x1040
	PT_MV_CLSID     = 0x1048
	PT_MV_BINARY    = 0x1102
)

// PropertyInfo contains metadata for a MAPI property
type PropertyInfo struct {
	Type      uint16 // Property type (unicode when possible)
	LDAPName  string // Active Directory LDAP-Display-Name
	CN        string // Active Directory CN
	PartialAS int    // Is-Member-Of-Partial-Attribute-Set (1=TRUE, 2=FALSE, 3=N/A, 4=not AD)
	CanonName string // MS-OXPROPS Canonical Name
	AltName   string // MS-OXPROPS First Alternate Name (usually starts with PR_)
}

// Properties is a map of PropertyID to PropertyInfo
// Contains the most commonly used properties for exchanger tool
var Properties = map[uint16]PropertyInfo{
	// Non-AD MAPI properties (PAS=4, no LDAP name)
	0x0ff6: {PT_BINARY, "", "", 4, "PidTagInstanceKey", "PR_INSTANCE_KEY"},
	0x0ff8: {PT_BINARY, "", "", 4, "PidTagMappingSignature", "PR_MAPPING_SIGNATURE"},
	0x0ff9: {PT_BINARY, "", "", 4, "PidTagRecordKey", "PR_RECORD_KEY"},
	0x0ffe: {PT_LONG, "", "", 4, "PidTagObjectType", "PR_OBJECT_TYPE"},
	0x0fff: {PT_BINARY, "", "", 4, "PidTagEntryId", "PR_ENTRYID"},
	0x3001: {PT_UNICODE, "", "", 4, "PidTagDisplayName", "PR_DISPLAY_NAME"},
	0x3002: {PT_UNICODE, "", "", 4, "PidTagAddressType", "PR_ADDRTYPE"},
	0x3003: {PT_UNICODE, "", "", 4, "PidTagEmailAddress", "PR_EMAIL_ADDRESS"},
	0x300b: {PT_BINARY, "", "", 4, "PidTagSearchKey", "PR_SEARCH_KEY"},
	// AD MAPI properties
	0x3004: {PT_UNICODE, "info", "Comment", 1, "PidTagComment", "PR_COMMENT"},
	0x3007: {PT_SYSTIME, "whenCreated", "When-Created", 1, "PidTagCreationTime", "PR_CREATION_TIME"},
	0x3008: {PT_SYSTIME, "whenChanged", "When-Changed", 1, "PidTagLastModificationTime", "PR_LAST_MODIFICATION_TIME"},
	0x3900: {PT_LONG, "", "", 4, "PidTagDisplayType", "PR_DISPLAY_TYPE"},
	0x3902: {PT_BINARY, "", "", 4, "PidTagTemplateid", "PR_TEMPLATEID"},
	0x3905: {PT_LONG, "msExchRecipientDisplayType", "ms-Exch-Recipient-Display-Type", 1, "PidTagDisplayTypeEx", "PR_DISPLAY_TYPE_EX"},
	0x39fe: {PT_UNICODE, "mail", "E-mail-Addresses", 1, "PidTagSmtpAddress", "PR_SMTP_ADDRESS"},
	0x39ff: {PT_UNICODE, "displayNamePrintable", "Display-Name-Printable", 1, "PidTagAddressBookDisplayNamePrintable", "PR_EMS_AB_DISPLAY_NAME_PRINTABLE"},
	0x3a00: {PT_UNICODE, "mailNickname", "ms-Exch-Mail-Nickname", 1, "PidTagAccount", "PR_ACCOUNT"},
	0x3a06: {PT_UNICODE, "givenName", "Given-Name", 1, "PidTagGivenName", "PR_GIVEN_NAME"},
	0x3a08: {PT_UNICODE, "telephoneNumber", "Telephone-Number", 1, "PidTagBusinessTelephoneNumber", "PR_BUSINESS_TELEPHONE_NUMBER"},
	0x3a09: {PT_UNICODE, "homePhone", "Phone-Home-Primary", 1, "PidTagHomeTelephoneNumber", "PR_HOME_TELEPHONE_NUMBER"},
	0x3a0a: {PT_UNICODE, "initials", "Initials", 1, "PidTagInitials", "PR_INITIALS"},
	0x3a0f: {PT_UNICODE, "cn", "Common-Name", 1, "PidTagMessageHandlingSystemCommonName", "PR_MHS_COMMON_NAME"},
	0x3a11: {PT_UNICODE, "sn", "Surname", 1, "PidTagSurname", "PR_SURNAME"},
	0x3a16: {PT_UNICODE, "company", "Company", 1, "PidTagCompanyName", "PR_COMPANY_NAME"},
	0x3a17: {PT_UNICODE, "title", "Title", 1, "PidTagTitle", "PR_TITLE"},
	0x3a18: {PT_UNICODE, "department", "Department", 1, "PidTagDepartmentName", "PR_DEPARTMENT_NAME"},
	0x3a1b: {PT_MV_UNICODE, "otherTelephone", "Phone-Office-Other", 1, "PidTagBusiness2TelephoneNumbers", "PR_BUSINESS2_TELEPHONE_NUMBER_A_MV"},
	0x3a1c: {PT_UNICODE, "mobile", "Phone-Mobile-Primary", 1, "PidTagMobileTelephoneNumber", "PR_MOBILE_TELEPHONE_NUMBER"},
	0x3a20: {PT_UNICODE, "", "", 4, "PidTagTransmittableDisplayName", "PR_TRANSMITABLE_DISPLAY_NAME"},
	0x3a26: {PT_UNICODE, "co", "Text-Country", 1, "PidTagCountry", "PR_COUNTRY"},
	0x3a28: {PT_UNICODE, "st", "State-Or-Province-Name", 1, "PidTagStateOrProvince", "PR_STATE_OR_PROVINCE"},
	0x3a29: {PT_UNICODE, "streetAddress", "Address", 1, "PidTagStreetAddress", "PR_STREET_ADDRESS"},
	0x3a2a: {PT_UNICODE, "postalCode", "Postal-Code", 1, "PidTagPostalCode", "PR_POSTAL_CODE"},
	0x68c4: {PT_BINARY, "", "", 4, "", "ExchangeObjectId"},
	0x8027: {PT_BINARY, "objectSid", "Object-Sid", 1, "", ""},
	0x8029: {PT_LONG, "uSNChanged", "USN-Changed", 1, "", ""},
	0x800f: {PT_MV_UNICODE, "proxyAddresses", "Proxy-Addresses", 1, "PidTagAddressBookProxyAddresses", "PR_EMS_AB_PROXY_ADDRESSES"},
	0x803c: {PT_UNICODE, "distinguishedName", "Obj-Dist-Name", 1, "", ""},
	0x8069: {PT_UNICODE, "c", "Country-Name", 1, "", ""},
	0x806f: {PT_MV_UNICODE, "description", "Description", 1, "", ""},
	0x80bd: {PT_LONG, "instanceType", "Instance-Type", 1, "", ""},
	0x80d4: {PT_BOOLEAN, "mDBUseDefaults", "ms-Exch-MDB-Use-Defaults", 1, "", ""},
	0x8102: {PT_MV_UNICODE, "ou", "", 1, "", ""},
	0x8154: {PT_LONG, "uSNCreated", "USN-Created", 1, "", ""},
	0x8170: {PT_MV_STRING8, "networkAddress", "Network-Address", 1, "", ""},
	0x8171: {PT_UNICODE, "lDAPDisplayName", "LDAP-Display-Name", 1, "", ""},
	0x8175: {PT_MV_STRING8, "url", "WWW-Page-Other", 1, "", ""},
	0x8202: {PT_UNICODE, "name", "RDN", 1, "", ""},
	0x802d: {PT_UNICODE, "extensionAttribute1", "ms-Exch-Extension-Attribute-1", 1, "PidTagAddressBookExtensionAttribute1", "PR_EMS_AB_EXTENSION_ATTRIBUTE_1"},
	0x802e: {PT_UNICODE, "extensionAttribute2", "ms-Exch-Extension-Attribute-2", 1, "PidTagAddressBookExtensionAttribute2", "PR_EMS_AB_EXTENSION_ATTRIBUTE_2"},
	0x802f: {PT_UNICODE, "extensionAttribute3", "ms-Exch-Extension-Attribute-3", 1, "PidTagAddressBookExtensionAttribute3", "PR_EMS_AB_EXTENSION_ATTRIBUTE_3"},
	0x8030: {PT_UNICODE, "extensionAttribute4", "ms-Exch-Extension-Attribute-4", 1, "PidTagAddressBookExtensionAttribute4", "PR_EMS_AB_EXTENSION_ATTRIBUTE_4"},
	0x8031: {PT_UNICODE, "extensionAttribute5", "ms-Exch-Extension-Attribute-5", 1, "PidTagAddressBookExtensionAttribute5", "PR_EMS_AB_EXTENSION_ATTRIBUTE_5"},
	0x8032: {PT_UNICODE, "extensionAttribute6", "ms-Exch-Extension-Attribute-6", 1, "PidTagAddressBookExtensionAttribute6", "PR_EMS_AB_EXTENSION_ATTRIBUTE_6"},
	0x8033: {PT_UNICODE, "extensionAttribute7", "ms-Exch-Extension-Attribute-7", 1, "PidTagAddressBookExtensionAttribute7", "PR_EMS_AB_EXTENSION_ATTRIBUTE_7"},
	0x8034: {PT_UNICODE, "extensionAttribute8", "ms-Exch-Extension-Attribute-8", 1, "PidTagAddressBookExtensionAttribute8", "PR_EMS_AB_EXTENSION_ATTRIBUTE_8"},
	0x8035: {PT_UNICODE, "extensionAttribute9", "ms-Exch-Extension-Attribute-9", 1, "PidTagAddressBookExtensionAttribute9", "PR_EMS_AB_EXTENSION_ATTRIBUTE_9"},
	0x8036: {PT_UNICODE, "extensionAttribute10", "ms-Exch-Extension-Attribute-10", 1, "PidTagAddressBookExtensionAttribute10", "PR_EMS_AB_EXTENSION_ATTRIBUTE_10"},
	0x804b: {PT_UNICODE, "adminDisplayName", "Admin-Display-Name", 1, "", ""},
	0x8011: {PT_STRING8, "targetAddress", "ms-Exch-Target-Address", 1, "PidTagAddressBookTargetAddress", "PR_EMS_AB_TARGET_ADDRESS"},
	0x813b: {PT_MV_STRING8, "subRefs", "Sub-Refs", 1, "", ""},
	0x81b6: {PT_MV_STRING8, "protocolSettings", "ms-Exch-Protocol-Settings", 1, "", ""},
	0x8c57: {PT_UNICODE, "extensionAttribute11", "ms-Exch-Extension-Attribute-11", 1, "", ""},
	0x8c58: {PT_UNICODE, "extensionAttribute12", "ms-Exch-Extension-Attribute-12", 1, "", ""},
	0x8c59: {PT_UNICODE, "extensionAttribute13", "ms-Exch-Extension-Attribute-13", 1, "", ""},
	0x8c60: {PT_UNICODE, "extensionAttribute14", "ms-Exch-Extension-Attribute-14", 1, "", ""},
	0x8c61: {PT_UNICODE, "extensionAttribute15", "ms-Exch-Extension-Attribute-15", 1, "", ""},
	0x8c6a: {PT_MV_BINARY, "userCertificate", "User-Certificate", 1, "", ""},
	0x8c6d: {PT_BINARY, "objectGUID", "Object-GUID", 1, "", ""},
	0x8c73: {PT_BINARY, "msExchMailboxGuid", "ms-Exch-Mailbox-Guid", 1, "", ""},
	0x8c75: {PT_BINARY, "msExchMasterAccountSid", "ms-Exch-Master-Account-Sid", 1, "", ""},
	0x8c96: {PT_MV_STRING8, "msExchResourceAddressLists", "ms-Exch-Resource-Address-Lists", 1, "", ""},
	0x8c9f: {PT_STRING8, "msExchUserCulture", "ms-Exch-User-Culture", 1, "", ""},
	0x8cb3: {PT_LONG, "msExchGroupJoinRestriction", "ms-Exch-Group-Join-Restriction", 1, "", ""},
	0x8cb5: {PT_BOOLEAN, "msExchEnableModeration", "ms-Exch-Enable-Moderation", 1, "", ""},
	0x8ce2: {PT_LONG, "msExchGroupMemberCount", "ms-Exch-Group-Member-Count", 1, "", ""},
}

// GetPropertyName returns the human-readable name for a property tag.
// Prefers LDAP Display Name, then PR_ alternate name, then canonical name
// (matching Impacket's print_row behavior).
func GetPropertyName(propTag uint32) string {
	propID := uint16(propTag >> 16)
	if info, ok := Properties[propID]; ok {
		if info.LDAPName != "" {
			return info.LDAPName
		}
		if info.AltName != "" {
			return info.AltName
		}
		if info.CanonName != "" {
			return info.CanonName
		}
	}
	return ""
}

// ParseBitmask parses a bitmask value and returns the set flags as strings
func ParseBitmask(values map[uint32]string, mask uint32) []string {
	var result []string
	for flag, name := range values {
		if mask&flag != 0 {
			result = append(result, name)
		}
	}
	return result
}
