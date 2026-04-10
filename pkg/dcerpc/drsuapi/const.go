// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jacob Paullus

package drsuapi

// Operation numbers
const (
	OpDsBind              = 0
	OpDsUnbind            = 1
	OpDsReplicaSync       = 2
	OpDsGetNCChanges      = 3
	OpDsReplicaUpdateRefs = 4
	OpDsReplicaAdd        = 5
	OpDsCrackNames        = 12
	OpDsGetDCInfo         = 16
)

// DRS_EXT flags for client/server capabilities
const (
	DRS_EXT_BASE                         = 0x00000001
	DRS_EXT_ASYNCREPL                    = 0x00000002
	DRS_EXT_REMOVEAPI                    = 0x00000004
	DRS_EXT_MOVEREQ_V2                   = 0x00000008
	DRS_EXT_GETCHG_DEFLATE               = 0x00000010
	DRS_EXT_DCINFO_V1                    = 0x00000020
	DRS_EXT_RESTORE_USN_OPTIMIZATION     = 0x00000040
	DRS_EXT_ADDENTRY                     = 0x00000080
	DRS_EXT_KCC_EXECUTE                  = 0x00000100
	DRS_EXT_ADDENTRY_V2                  = 0x00000200
	DRS_EXT_LINKED_VALUE_REPLICATION     = 0x00000400
	DRS_EXT_DCINFO_V2                    = 0x00000800
	DRS_EXT_INSTANCE_TYPE_NOT_REQ_ON_MOD = 0x00001000
	DRS_EXT_CRYPTO_BIND                  = 0x00002000
	DRS_EXT_GET_REPL_INFO                = 0x00004000
	DRS_EXT_STRONG_ENCRYPTION            = 0x00008000
	DRS_EXT_DCINFO_V01                   = 0x00010000
	DRS_EXT_TRANSITIVE_MEMBERSHIP        = 0x00020000
	DRS_EXT_ADD_SID_HISTORY              = 0x00040000
	DRS_EXT_POST_BETA3                   = 0x00080000
	DRS_EXT_GETCHGREQ_V5                 = 0x00100000
	DRS_EXT_GETMEMBERSHIPS2              = 0x00200000
	DRS_EXT_GETCHGREQ_V6                 = 0x00400000
	DRS_EXT_NONDOMAIN_NCS                = 0x00800000
	DRS_EXT_GETCHGREQ_V8                 = 0x01000000
	DRS_EXT_GETCHGREPLY_V5               = 0x02000000
	DRS_EXT_GETCHGREPLY_V6               = 0x04000000
	DRS_EXT_ADDENTRYREPLY_V3             = 0x08000000
	DRS_EXT_GETCHGREPLY_V7               = 0x08000000
	DRS_EXT_VERIFY_OBJECT                = 0x08000000
	DRS_EXT_XPRESS_COMPRESS              = 0x10000000
	DRS_EXT_GETCHGREQ_V10                = 0x20000000
	DRS_EXT_RESERVED_FOR_WIN2K_OR_DOTNET = 0x80000000
)

// DS_NAME_FORMAT - name format types for DsCrackNames
const (
	DS_UNKNOWN_NAME                 = 0
	DS_FQDN_1779_NAME               = 1 // CN=John,OU=Users,DC=example,DC=com
	DS_NT4_ACCOUNT_NAME             = 2 // DOMAIN\username
	DS_DISPLAY_NAME                 = 3
	DS_UNIQUE_ID_NAME               = 6 // GUID string
	DS_CANONICAL_NAME               = 7 // example.com/Users/John
	DS_USER_PRINCIPAL_NAME          = 8 // user@domain.com
	DS_CANONICAL_NAME_EX            = 9
	DS_SERVICE_PRINCIPAL_NAME       = 10
	DS_SID_OR_SID_HISTORY_NAME      = 11
	DS_DNS_DOMAIN_NAME              = 12  // domain.com
	DS_NT4_ACCOUNT_NAME_SANS_DOMAIN = 0xb // username (no domain prefix)
)

// DS_NAME_FLAGS
const (
	DS_NAME_NO_FLAGS              = 0x0
	DS_NAME_FLAG_SYNTACTICAL_ONLY = 0x1
	DS_NAME_FLAG_EVAL_AT_DC       = 0x2
	DS_NAME_FLAG_GCVERIFY         = 0x4
	DS_NAME_FLAG_TRUST_REFERRAL   = 0x8
)

// DS_NAME_ERROR - error codes from DsCrackNames
const (
	DS_NAME_NO_ERROR                     = 0
	DS_NAME_ERROR_RESOLVING              = 1
	DS_NAME_ERROR_NOT_FOUND              = 2
	DS_NAME_ERROR_NOT_UNIQUE             = 3
	DS_NAME_ERROR_NO_MAPPING             = 4
	DS_NAME_ERROR_DOMAIN_ONLY            = 5
	DS_NAME_ERROR_NO_SYNTACTICAL_MAPPING = 6
	DS_NAME_ERROR_TRUST_REFERRAL         = 7
)

// DRSUAPI_ATTID - attribute IDs (matching Impacket's NAME_TO_ATTRTYP)
const (
	DRSUAPI_ATTID_objectSid               = 0x00090092 // 1.2.840.113556.1.4.146
	DRSUAPI_ATTID_sAMAccountName          = 0x000900DD // 1.2.840.113556.1.4.221 (was wrong: 0x45)
	DRSUAPI_ATTID_userPrincipalName       = 0x00090290 // 1.2.840.113556.1.4.656
	DRSUAPI_ATTID_sAMAccountType          = 0x0009004e
	DRSUAPI_ATTID_userAccountControl      = 0x00090008 // 1.2.840.113556.1.4.8
	DRSUAPI_ATTID_accountExpires          = 0x0009005f
	DRSUAPI_ATTID_pwdLastSet              = 0x00090060 // 1.2.840.113556.1.4.96
	DRSUAPI_ATTID_objectGUID              = 0x00090048
	DRSUAPI_ATTID_objectClass             = 0x00000000
	DRSUAPI_ATTID_cn                      = 0x00000003
	DRSUAPI_ATTID_description             = 0x0000000d
	DRSUAPI_ATTID_unicodePwd              = 0x0009005a // 1.2.840.113556.1.4.90
	DRSUAPI_ATTID_ntPwdHistory            = 0x0009005e // 1.2.840.113556.1.4.94
	DRSUAPI_ATTID_dBCSPwd                 = 0x00090037 // 1.2.840.113556.1.4.55
	DRSUAPI_ATTID_lmPwdHistory            = 0x000900a0 // 1.2.840.113556.1.4.160
	DRSUAPI_ATTID_supplementalCredentials = 0x0009007d // 1.2.840.113556.1.4.125
	DRSUAPI_ATTID_member                  = 0x0001f401
)

// DRS_OPTIONS flags for GetNCChanges
const (
	DRS_INIT_SYNC                 = 0x00000020
	DRS_WRIT_REP                  = 0x00000010
	DRS_INIT_SYNC_NOW             = 0x00800000
	DRS_FULL_SYNC_NOW             = 0x00008000
	DRS_SYNC_URGENT               = 0x00080000
	DRS_GET_ANC                   = 0x00000200
	DRS_GET_NC_SIZE               = 0x00001000
	DRS_SPECIAL_SECRET_PROCESSING = 0x00002000
	DRS_CRITICAL_ONLY             = 0x00000004
)

// EXOP codes for extended operations
const (
	EXOP_NONE              = 0
	EXOP_FSMO_REQ_ROLE     = 1
	EXOP_FSMO_RID_ALLOC    = 2
	EXOP_FSMO_RID_REQ_ROLE = 3
	EXOP_FSMO_REQ_PDC      = 4
	EXOP_FSMO_ABANDON_ROLE = 5
	EXOP_REPL_OBJ          = 6
	EXOP_REPL_SECRETS      = 7
)
