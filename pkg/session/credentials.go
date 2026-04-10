// SPDX-License-Identifier: Apache-2.0

package session

// Credentials holds authentication information.
type Credentials struct {
	Domain      string
	Username    string
	Password    string
	Hash        string
	UseKerberos bool
	DCHost      string
	DCIP        string
	AESKey      string
	Keytab      string // Path to keytab file for Kerberos authentication
}
