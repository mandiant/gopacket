// Copyright 2026 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package main

import (
	"encoding/binary"
	"testing"
	"unicode/utf16"
)

// utf16le encodes s as UTF-16LE bytes, matching how Windows LAPS stores the
// decrypted password blob.
func utf16le(s string) []byte {
	u := utf16.Encode([]rune(s))
	b := make([]byte, len(u)*2)
	for i, r := range u {
		binary.LittleEndian.PutUint16(b[i*2:], r)
	}
	return b
}

// TestDecryptedBlobParsing guards the UTF-16LE decode + JSON parse path. The
// '}' that closes the object encodes as the two bytes 7D 00; a prior version
// truncated on the 7D and dropped the trailing 00, silently deleting the brace
// and failing every parse. Windows LAPS also appends trailing metadata after
// the object, which must not break the parse.
func TestDecryptedBlobParsing(t *testing.T) {
	const wantUser = "Administrator"
	const wantPass = "++Jf%0uQs4(amVm@c5K@"
	obj := `{"n":"Administrator","t":"1dd1597e9faef4e","p":"++Jf%0uQs4(amVm@c5K@"}`

	cases := []struct {
		name string
		blob []byte
	}{
		{"bare object", utf16le(obj)},
		{"nul terminated", append(utf16le(obj), 0x00, 0x00)},
		{"nul then metadata", append(append(utf16le(obj), 0x00, 0x00), 0xde, 0xad, 0xbe, 0xef)},
		{"metadata without nul", append(utf16le(obj), utf16le("trailing-metadata")...)},
		{"password containing brace", utf16le(`{"n":"Administrator","t":"1dd","p":"pa}ss"}`)},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s := utf16ToString(tc.blob)
			user, pass, ok := parseLAPSv2JSON(s)
			if !ok {
				t.Fatalf("parse failed; decoded=%q", s)
			}
			if tc.name == "password containing brace" {
				if user != "Administrator" || pass != "pa}ss" {
					t.Fatalf("got (%q,%q), want (Administrator, pa}ss)", user, pass)
				}
				return
			}
			if user != wantUser || pass != wantPass {
				t.Fatalf("got (%q,%q), want (%q,%q)", user, pass, wantUser, wantPass)
			}
		})
	}
}
