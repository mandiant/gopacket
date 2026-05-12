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

package smb

import (
	"errors"
	"os"

	"github.com/mandiant/gopacket/pkg/third_party/smb2"
)

// NTSTATUS values from [MS-ERREF]. The smb2 erref package is internal, so we
// match the codes on *smb2.ResponseError.Code directly.
const (
	ntStatusObjectNameNotFound uint32 = 0xC0000034
	ntStatusObjectPathNotFound uint32 = 0xC000003A
	ntStatusSharingViolation   uint32 = 0xC0000043
)

// IsSharingViolation reports whether err wraps STATUS_SHARING_VIOLATION.
// The smb2 client wraps server responses in *os.PathError → *smb2.ResponseError,
// so substring matching on err.Error() is unreliable.
func IsSharingViolation(err error) bool {
	return ntStatusIs(err, ntStatusSharingViolation)
}

// IsNotFound reports whether err means the SMB target file or path does not
// exist. The smb2 layer translates STATUS_OBJECT_NAME_NOT_FOUND and
// STATUS_OBJECT_PATH_NOT_FOUND to os.ErrNotExist in conn.go before wrapping,
// so most call sites see the sentinel rather than an *smb2.ResponseError.
// We accept both forms.
func IsNotFound(err error) bool {
	if errors.Is(err, os.ErrNotExist) {
		return true
	}
	return ntStatusIs(err, ntStatusObjectNameNotFound) ||
		ntStatusIs(err, ntStatusObjectPathNotFound)
}

func ntStatusIs(err error, want uint32) bool {
	if err == nil {
		return false
	}
	var pe *os.PathError
	if errors.As(err, &pe) {
		err = pe.Err
	}
	var re *smb2.ResponseError
	if errors.As(err, &re) {
		return re.Code == want
	}
	return false
}
