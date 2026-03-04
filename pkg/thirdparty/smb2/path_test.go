package smb2

import (
	"testing"
)

var testBase = []struct {
	Path string
	Base string
}{
	{"", ""},
	{`\`, ""},
	{`\foo`, "foo"},
	{`\foo\bar`, "bar"},
	{`foo\bar`, "bar"},
	{`foo\bar\`, "bar"},
	{`foo\bar\\`, "bar"},
	{`foo`, "foo"},
}

func TestBase(t *testing.T) {
	for _, c := range testBase {
		if base(c.Path) != c.Base {
			t.Errorf("path: %v, expected: %v, got: %v", c.Path, c.Base, base(c.Path))
		}
	}
}

var testDir = []struct {
	Path string
	Dir  string
}{
	{"", ""},
	{`\`, `\`},
	{`\foo`, `\`},
	{`\foo\bar`, `\foo`},
	{`foo\bar`, "foo"},
	{`foo\bar\`, "foo"},
	{`foo\bar\\`, "foo"},
	{`foo`, ""},
}

func TestDir(t *testing.T) {
	for _, c := range testDir {
		if dir(c.Path) != c.Dir {
			t.Errorf("path: %v, expected: %v, got: %v", c.Path, c.Dir, base(c.Path))
		}
	}
}

var testMountPath = []struct {
	Path string
	Ok   bool
}{
	{`\\server\share`, true},
	{`\\server\share\`, false},
	{`\\server\share\file`, false},
	{`\\127.0.0.1\share`, true},
	{`\\[0:0:0:0:0:0:0:1]\share`, true},
}

func TestValidateMountPath(t *testing.T) {
	for _, c := range testMountPath {
		if err := validateMountPath(c.Path); err == nil != c.Ok {
			t.Errorf("path: %v, expected: %v, got: %v", c.Path, c.Ok, err == nil)
		}
	}
}
