// SPDX-License-Identifier: Apache-2.0

package build

import (
	"fmt"
	"os"
	"time"
)

var Debug bool
var Timestamp bool

// Logger is a global logger that respects the Timestamp flag.
func Log(format string, v ...interface{}) {
	msg := fmt.Sprintf(format, v...)
	if Timestamp {
		t := time.Now().Format("2006-01-02 15:04:05")
		msg = fmt.Sprintf("%s %s", t, msg)
	}
	fmt.Fprintln(os.Stderr, msg)
}

// DebugLog prints only if Debug is enabled.
func DebugLog(format string, v ...interface{}) {
	if Debug {
		Log("[D] "+format, v...)
	}
}
