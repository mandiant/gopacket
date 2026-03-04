package smb2

import (
	"strings"
	"testing"
)

func TestSimplifyPattern(t *testing.T) {
	cases := [][2]string{
		{"test.ext", "test.ext"},
		{"ab[0-9].ext", "ab?.ext"},
		{"tes?", "tes?"},
	}

	for _, tt := range cases {
		if simplifyPattern(tt[0]) != tt[1] {
			t.Errorf("simplifyPattern(%q) = %q, want %q", tt[0], simplifyPattern(tt[0]), tt[1])
		}
	}
}

func TestMatch(t *testing.T) {
	type matchTest struct {
		pattern, s string
		match      bool
		err        error
	}

	var cases = []matchTest{
		{"abc", "abc", true, nil},
		{"*", "abc", true, nil},
		{"*c", "abc", true, nil},
		{"a*", "a", true, nil},
		{"a*", "abc", true, nil},
		{"a*", "ab/c", false, nil},
		{"a*/b", "abc/b", true, nil},
		{"a*/b", "a/c/b", false, nil},
		{"a*b*c*d*e*/f", "axbxcxdxe/f", true, nil},
		{"a*b*c*d*e*/f", "axbxcxdxexxx/f", true, nil},
		{"a*b*c*d*e*/f", "axbxcxdxe/xxx/f", false, nil},
		{"a*b*c*d*e*/f", "axbxcxdxexxx/fff", false, nil},
		{"a*b?c*x", "abxbbxdbxebxczzx", true, nil},
		{"a*b?c*x", "abxbbxdbxebxczzy", false, nil},
		{"ab[c]", "abc", true, nil},
		{"ab[b-d]", "abc", true, nil},
		{"ab[e-g]", "abc", false, nil},
		{"ab[^c]", "abc", false, nil},
		{"ab[^b-d]", "abc", false, nil},
		{"ab[^e-g]", "abc", true, nil},
		{"a?b", "a☺b", true, nil},
		{"a[^a]b", "a☺b", true, nil},
		{"a???b", "a☺b", false, nil},
		{"a[^a][^a][^a]b", "a☺b", false, nil},
		{"[a-ζ]*", "α", true, nil},
		{"*[a-ζ]", "A", false, nil},
		{"a?b", "a/b", false, nil},
		{"a*b", "a/b", false, nil},
		{"[]a]", "]", false, ErrBadPattern},
		{"[-]", "-", false, ErrBadPattern},
		{"[x-]", "x", false, ErrBadPattern},
		{"[x-]", "-", false, ErrBadPattern},
		{"[x-]", "z", false, ErrBadPattern},
		{"[-x]", "x", false, ErrBadPattern},
		{"[-x]", "-", false, ErrBadPattern},
		{"[-x]", "a", false, ErrBadPattern},
		{"[a-b-c]", "a", false, ErrBadPattern},
		{"[", "a", false, ErrBadPattern},
		{"[^", "a", false, ErrBadPattern},
		{"[^bc", "a", false, ErrBadPattern},
		{"a[", "a", false, ErrBadPattern},
		{"a[", "ab", false, ErrBadPattern},
		{"a[", "x", false, ErrBadPattern},
		{"a/b[", "x", false, ErrBadPattern},
		{"*x", "xxx", true, nil},
	}

	errp := func(e error) string {
		if e == nil {
			return "<nil>"
		}
		return e.Error()
	}

	for _, tt := range cases {
		pattern := tt.pattern
		s := strings.Replace(tt.s, `/`, `\`, -1)
		ok, err := Match(pattern, s)
		if ok != tt.match || err != tt.err {
			t.Errorf("Match(%#q, %#q) = %v, %q want %v, %q", pattern, s, ok, errp(err), tt.match, errp(tt.err))
		}
	}
}
