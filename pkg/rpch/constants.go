// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jacob Paullus

// Package rpch implements RPC over HTTP v2 transport as per MS-RPCH specification.
// This is a modular library that can be used by multiple tools for Exchange and
// other RPC over HTTP services.
package rpch

// RPC over HTTP versions
const (
	RPC_OVER_HTTP_V1 = 1
	RPC_OVER_HTTP_V2 = 2
)

// Error strings for common RPC Proxy errors
const (
	RPC_PROXY_REMOTE_NAME_NEEDED_ERR = "Basic authentication in RPC proxy is used, so couldn't obtain a target NetBIOS name from NTLMSSP to connect"
	RPC_PROXY_INVALID_RPC_PORT_ERR   = "Invalid RPC Port"
	RPC_PROXY_CONN_A1_0X6BA_ERR      = "RPC Proxy CONN/A1 request failed, code: 0x6ba"
	RPC_PROXY_CONN_A1_404_ERR        = "CONN/A1 request failed: HTTP/1.1 404 Not Found"
	RPC_PROXY_RPC_OUT_DATA_404_ERR   = "RPC_OUT_DATA channel: HTTP/1.1 404 Not Found"
	RPC_PROXY_CONN_A1_401_ERR        = "CONN/A1 request failed: HTTP/1.1 401 Unauthorized"
	RPC_PROXY_HTTP_IN_DATA_401_ERR   = "RPC_IN_DATA channel: HTTP/1.1 401 Unauthorized"
)

// Forward Destinations (2.2.3.3)
const (
	FDClient   = 0x00000000
	FDInProxy  = 0x00000001
	FDServer   = 0x00000002
	FDOutProxy = 0x00000003
)

// RTS Flags (2.2.3.6)
const (
	RTS_FLAG_NONE            = 0x0000
	RTS_FLAG_PING            = 0x0001
	RTS_FLAG_OTHER_CMD       = 0x0002
	RTS_FLAG_RECYCLE_CHANNEL = 0x0004
	RTS_FLAG_IN_CHANNEL      = 0x0008
	RTS_FLAG_OUT_CHANNEL     = 0x0010
	RTS_FLAG_EOF             = 0x0020
	RTS_FLAG_ECHO            = 0x0040
)

// RTS Commands (2.2.3.5)
const (
	RTS_CMD_RECEIVE_WINDOW_SIZE      = 0x00000000
	RTS_CMD_FLOW_CONTROL_ACK         = 0x00000001
	RTS_CMD_CONNECTION_TIMEOUT       = 0x00000002
	RTS_CMD_COOKIE                   = 0x00000003
	RTS_CMD_CHANNEL_LIFETIME         = 0x00000004
	RTS_CMD_CLIENT_KEEPALIVE         = 0x00000005
	RTS_CMD_VERSION                  = 0x00000006
	RTS_CMD_EMPTY                    = 0x00000007
	RTS_CMD_PADDING                  = 0x00000008
	RTS_CMD_NEGATIVE_ANCE            = 0x00000009
	RTS_CMD_ANCE                     = 0x0000000A
	RTS_CMD_CLIENT_ADDRESS           = 0x0000000B
	RTS_CMD_ASSOCIATION_GROUP_ID     = 0x0000000C
	RTS_CMD_DESTINATION              = 0x0000000D
	RTS_CMD_PING_TRAFFIC_SENT_NOTIFY = 0x0000000E
)

// Default values
const (
	DEFAULT_RECEIVE_WINDOW_SIZE = 262144
	DEFAULT_CONNECTION_TIMEOUT  = 120000 // 2 minutes in ms
	DEFAULT_CHANNEL_LIFETIME    = 1073741824
	DEFAULT_CLIENT_KEEPALIVE    = 300000 // 5 minutes in ms
	DEFAULT_RTS_VERSION         = 1
)

// RPC packet types
const (
	MSRPC_REQUEST           = 0
	MSRPC_PING              = 1
	MSRPC_RESPONSE          = 2
	MSRPC_FAULT             = 3
	MSRPC_WORKING           = 4
	MSRPC_NOCALL            = 5
	MSRPC_REJECT            = 6
	MSRPC_ACK               = 7
	MSRPC_CL_CANCEL         = 8
	MSRPC_FACK              = 9
	MSRPC_CANCEL_ACK        = 10
	MSRPC_BIND              = 11
	MSRPC_BINDACK           = 12
	MSRPC_BINDNACK          = 13
	MSRPC_ALTERCONTEXT      = 14
	MSRPC_ALTERCONTEXT_RESP = 15
	MSRPC_AUTH3             = 16
	MSRPC_SHUTDOWN          = 17
	MSRPC_CO_CANCEL         = 18
	MSRPC_ORPHANED          = 19
	MSRPC_RTS               = 20
)

// RPC flags
const (
	PFC_FIRST_FRAG      = 0x01
	PFC_LAST_FRAG       = 0x02
	PFC_PENDING_CANCEL  = 0x04
	PFC_RESERVED_1      = 0x08
	PFC_CONC_MPX        = 0x10
	PFC_DID_NOT_EXECUTE = 0x20
	PFC_MAYBE           = 0x40
	PFC_OBJECT_UUID     = 0x80
)

// Authentication levels
const (
	RPC_C_AUTHN_LEVEL_NONE          = 1
	RPC_C_AUTHN_LEVEL_CONNECT       = 2
	RPC_C_AUTHN_LEVEL_CALL          = 3
	RPC_C_AUTHN_LEVEL_PKT           = 4
	RPC_C_AUTHN_LEVEL_PKT_INTEGRITY = 5
	RPC_C_AUTHN_LEVEL_PKT_PRIVACY   = 6
)

// Authentication types
const (
	RPC_C_AUTHN_NONE          = 0
	RPC_C_AUTHN_DCE_PRIVATE   = 1
	RPC_C_AUTHN_DCE_PUBLIC    = 2
	RPC_C_AUTHN_DEC_PUBLIC    = 4
	RPC_C_AUTHN_GSS_NEGOTIATE = 9
	RPC_C_AUTHN_WINNT         = 10
	RPC_C_AUTHN_GSS_SCHANNEL  = 14
	RPC_C_AUTHN_GSS_KERBEROS  = 16
	RPC_C_AUTHN_DPA           = 17
	RPC_C_AUTHN_MSN           = 18
	RPC_C_AUTHN_KERNEL        = 20
	RPC_C_AUTHN_DIGEST        = 21
	RPC_C_AUTHN_NEGO_EXTENDER = 30
	RPC_C_AUTHN_PKU2U         = 31
	RPC_C_AUTHN_MQ            = 100
	RPC_C_AUTHN_DEFAULT       = 0xFFFFFFFF
)

// HTTP Methods
const (
	HTTP_METHOD_RPC_IN_DATA  = "RPC_IN_DATA"
	HTTP_METHOD_RPC_OUT_DATA = "RPC_OUT_DATA"
)
