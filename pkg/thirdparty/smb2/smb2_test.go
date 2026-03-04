// This package is used for integration testing.

package smb2_test

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"net"
	"os"
	"reflect"
	"sort"
	"strings"
	"time"

	"gopacket/pkg/thirdparty/smb2"

	"testing"
)

func join(ss ...string) string {
	return strings.Join(ss, `\`)
}

type transportConfig struct {
	Type string `json:"type"`
	Host string `json:"host"`
	Port int    `json:"port"`
}

type connConfig struct {
	RequireMessageSigning bool   `json:"signing"`
	ClientGuid            string `json:"guid"`
	SpecifiedDialect      uint16 `json:"dialect"`
}

type sessionConfig struct {
	Type        string `json:"type"`
	User        string `json:"user"`
	Password    string `json:"passwd"`
	Domain      string `json:"domain"`
	Workstation string `json:"workstation"`
	TargetSPN   string `json:"targetSPN"`
}

type treeConnConfig struct {
	Share1 string `json:"share1"`
	Share2 string `json:"share2"`
}

type config struct {
	MaxCreditBalance uint16          `json:"max_credit_balance"`
	Transport        transportConfig `json:"transport"`
	Conn             connConfig      `json:"conn,omitempty"`
	Session          sessionConfig   `json:"session,omitempty"`
	TreeConn         treeConnConfig  `json:"tree_conn"`
}

var cfg config
var fs *smb2.Share
var rfs *smb2.Share
var session *smb2.Session
var dialer *smb2.Dialer

func connect(f func()) {
	{
		cf, err := os.Open("client_conf.json")
		if err != nil {
			fmt.Println("cannot open client_conf.json")
			goto NO_CONNECTION
		}

		err = json.NewDecoder(cf).Decode(&cfg)
		if err != nil {
			fmt.Println("cannot decode client_conf.json")
			goto NO_CONNECTION
		}

		if cfg.Transport.Type != "tcp" {
			fmt.Println("unsupported transport type")
			goto NO_CONNECTION
		}

		conn, err := net.Dial(cfg.Transport.Type, fmt.Sprintf("%s:%d", cfg.Transport.Host, cfg.Transport.Port))
		if err != nil {
			panic(err)
		}
		defer conn.Close()

		if cfg.Session.Type != "ntlm" {
			panic("unsupported session type")
		}

		dialer = &smb2.Dialer{
			MaxCreditBalance: cfg.MaxCreditBalance,
			Negotiator: smb2.Negotiator{
				RequireMessageSigning: cfg.Conn.RequireMessageSigning,
				SpecifiedDialect:      cfg.Conn.SpecifiedDialect,
			},
			Initiator: &smb2.NTLMInitiator{
				User:        cfg.Session.User,
				Password:    cfg.Session.Password,
				Domain:      cfg.Session.Domain,
				Workstation: cfg.Session.Workstation,
				TargetSPN:   cfg.Session.TargetSPN,
			},
		}

		c, err := dialer.Dial(conn)
		if err != nil {
			panic(err)
		}
		defer c.Logoff()

		fs1, err := c.Mount(cfg.TreeConn.Share1)
		if err != nil {
			panic(err)
		}
		defer fs1.Umount()

		fs2, err := c.Mount(cfg.TreeConn.Share2)
		if err != nil {
			panic(err)
		}
		defer fs2.Umount()

		fs = fs1
		rfs = fs2
		session = c
	}
NO_CONNECTION:
	f()
}

func TestMain(m *testing.M) {
	var code int
	connect(func() {
		code = m.Run()
	})
	os.Exit(code)
}

func TestReaddir(t *testing.T) {
	if fs == nil {
		t.Skip()
	}
	testDir := fmt.Sprintf("testDir-%d-TestReaddir", os.Getpid())
	err := fs.Mkdir(testDir, 0755)
	if err != nil {
		t.Fatal(err)
	}
	defer fs.RemoveAll(testDir)

	d, err := fs.Open(testDir)
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()

	fi, err := d.Readdir(-1)
	if err != nil {
		t.Fatal(err)
	}
	if len(fi) != 0 {
		t.Error("unexpected content length:", len(fi))
	}

	f, err := fs.Create(testDir + `\testFile`)
	if err != nil {
		t.Fatal(err)
	}
	defer fs.Remove(testDir + `\testFile`)
	defer f.Close()

	d2, err := fs.Open(testDir)
	if err != nil {
		t.Fatal(err)
	}
	defer d2.Close()

	fi2, err := d2.Readdir(-1)
	if err != nil {
		t.Fatal(err)
	}
	if len(fi2) != 1 {
		t.Error("unexpected content length:", len(fi2))
	}

	fi2, err = d2.Readdir(1)
	if err != io.EOF {
		t.Error("unexpected error: ", err)
	}
}

func TestFile(t *testing.T) {
	if fs == nil {
		t.Skip()
	}
	testDir := fmt.Sprintf("testDir-%d-TestFile", os.Getpid())
	err := fs.Mkdir(testDir, 0755)
	if err != nil {
		t.Fatal(err)
	}
	defer fs.RemoveAll(testDir)

	f, err := fs.Create(testDir + `\testFile`)
	if err != nil {
		t.Fatal(err)
	}
	defer fs.Remove(testDir + `\testFile`)
	defer f.Close()

	if f.Name() != testDir+`\testFile` {
		t.Error("unexpected name:", f.Name())
	}

	n, err := f.Write([]byte("test"))
	if err != nil {
		t.Fatal(err)
	}

	if n != 4 {
		t.Error("unexpected content length:", n)
	}

	n, err = f.Write([]byte("Content"))
	if err != nil {
		t.Fatal(err)
	}

	if n != 7 {
		t.Error("unexpected content length:", n)
	}

	n64, err := f.Seek(0, io.SeekStart)
	if err != nil {
		t.Fatal(err)
	}

	if n64 != 0 {
		t.Error("unexpected seek length:", n64)
	}

	p := make([]byte, 10)

	n, err = f.Read(p)
	if err != nil {
		t.Fatal(err)
	}

	if n != 10 {
		t.Error("unexpected content length:", n)
	}

	if string(p) != "testConten" {
		t.Error("unexpected content:", string(p))
	}

	stat, err := f.Stat()
	if err != nil {
		t.Fatal(err)
	}

	if stat.Name() != "testFile" {
		t.Error("unexpected name:", stat.Name())
	}

	if stat.Size() != 11 {
		t.Error("unexpected content length:", n)
	}

	if stat.IsDir() {
		t.Error("should be not a directory")
	}

	f.Truncate(4)

	n64, err = f.Seek(-3, io.SeekEnd)
	if err != nil {
		t.Fatal(err)
	}

	if n64 != 1 {
		t.Error("unexpected seek length:", n64)
	}

	n, err = f.Read(p)
	if err != nil {
		t.Fatal(err)
	}

	if n != 3 {
		t.Error("unexpected content length:", n)
	}

	if string(p[:n]) != "est" {
		t.Error("unexpected content:", string(p))
	}
}

func TestSymlink(t *testing.T) {
	if fs == nil {
		t.Skip()
	}
	testDir := fmt.Sprintf("testDir-%d-TestSymlink", os.Getpid())
	err := fs.Mkdir(testDir, 0755)
	if err != nil {
		t.Fatal(err)
	}
	defer fs.RemoveAll(testDir)

	f, err := fs.Create(testDir + `\testFile`)
	if err != nil {
		t.Fatal(err)
	}
	defer fs.Remove(testDir + `\testFile`)
	defer f.Close()

	_, err = f.Write([]byte("testContent"))
	if err != nil {
		t.Fatal(err)
	}

	err = fs.Symlink(testDir+`\testFile`, testDir+`\linkToTestFile`)

	if !os.IsPermission(err) {
		if err != nil {
			t.Skip("samba doesn't support reparse point")
		}
		defer fs.Remove(testDir + `\linkToTestFile`)

		stat, err := fs.Lstat(testDir + `\linkToTestFile`)
		if err != nil {
			t.Fatal(err)
		}

		if stat.Name() != `linkToTestFile` {
			t.Error("unexpected name:", stat.Name())
		}

		if stat.Mode()&os.ModeSymlink == 0 {
			t.Error("should be a symlink")
		}

		target, err := fs.Readlink(testDir + `\linkToTestFile`)
		if err != nil {
			t.Fatal(err)
		}

		if target != testDir+`\testFile` {
			t.Error("unexpected target:", target)
		}

		f, err = fs.Open(testDir + `\linkToTestFile`)
		if err == nil { // if it supports follow-symlink
			bs, err := ioutil.ReadAll(f)
			if err != nil {
				t.Fatal(err)
			}
			if string(bs) != "testContent" {
				t.Error("unexpected content:", string(bs))
			}
		}
	}
}

func TestIsXXX(t *testing.T) {
	if fs == nil {
		t.Skip()
	}
	testDir := fmt.Sprintf("testDir-%d-TestIsXXX", os.Getpid())
	err := fs.Mkdir(testDir, 0755)
	if err != nil {
		t.Fatal(err)
	}
	defer fs.RemoveAll(testDir)

	f, err := fs.Create(testDir + `\Exist`)
	if err != nil {
		t.Fatal(err)
	}
	defer fs.Remove(testDir + `\Exist`)
	defer f.Close()

	_, err = fs.OpenFile(testDir+`\Exist`, os.O_CREATE|os.O_EXCL, 0666)
	if !os.IsExist(err) {
		t.Error("unexpected error:", err)
	}
	if os.IsNotExist(err) {
		t.Error("unexpected error:", err)
	}
	if os.IsPermission(err) {
		t.Error("unexpected error:", err)
	}
	if os.IsTimeout(err) {
		t.Error("unexpected error:", err)
	}

	_, err = fs.Open(testDir + `\notExist`)
	if os.IsExist(err) {
		t.Error("unexpected error:", err)
	}
	if !os.IsNotExist(err) {
		t.Error("unexpected error:", err)
	}
	if os.IsPermission(err) {
		t.Error("unexpected error:", err)
	}
	if os.IsTimeout(err) {
		t.Error("unexpected error:", err)
	}

	err = fs.WriteFile(testDir+`\aaa`, []byte("aaa"), 0444)
	if err != nil {
		t.Fatal(err)
	}
	err = fs.WriteFile(testDir+`\aaa`, []byte("aaa"), 0444)
	if !os.IsPermission(err) {
		t.Error("unexpected error:", err)
	}
	if os.IsTimeout(err) {
		t.Error("unexpected error:", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 0)
	defer cancel()
	fst := fs.WithContext(ctx)
	_, err = fst.Create(testDir + `\Exist`)
	if !os.IsTimeout(err) {
		t.Error("unexpected error:", err)
	}

	ctx, cancel = context.WithCancel(context.Background())
	cancel()
	fsc := fs.WithContext(ctx)
	_, err = fsc.Create(testDir + `\Exist`)
	if os.IsTimeout(err) {
		t.Error("unexpected error:", err)
	}
}

func TestRename(t *testing.T) {
	if fs == nil {
		t.Skip()
	}
	testDir := fmt.Sprintf("testDir-%d-TestRename", os.Getpid())
	err := fs.Mkdir(testDir, 0755)
	if err != nil {
		t.Fatal(err)
	}
	defer fs.RemoveAll(testDir)

	f, err := fs.Create(testDir + `\old`)
	if err != nil {
		t.Fatal(err)
	}
	_, err = f.Write([]byte("testContent"))
	if err != nil {
		t.Fatal(err)
	}
	err = f.Close()
	if err != nil {
		fs.Remove(testDir + `\old`)

		t.Fatal(err)
	}

	err = fs.Rename(testDir+`\old`, testDir+`\new`)
	if err != nil {
		fs.Remove(testDir + `\old`)

		t.Fatal(err)
	}
	defer fs.Remove(testDir + `\new`)

	_, err = fs.Stat(testDir + `\old`)
	if os.IsExist(err) {
		t.Error("unexpected error:", err)
	}
	f, err = fs.Open(testDir + `\new`)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	bs, err := ioutil.ReadAll(f)
	if err != nil {
		t.Fatal(err)
	}
	if string(bs) != "testContent" {
		t.Error("unexpected content:", string(bs))
	}
}

func TestChtimes(t *testing.T) {
	if fs == nil {
		t.Skip()
	}
	testDir := fmt.Sprintf("testDir-%d-TestChtimes", os.Getpid())
	err := fs.Mkdir(testDir, 0755)
	if err != nil {
		t.Fatal(err)
	}
	defer fs.RemoveAll(testDir)

	f, err := fs.Create(testDir + `\testFile`)
	if err != nil {
		t.Fatal(err)
	}
	err = f.Close()
	if err != nil {
		fs.Remove(testDir + `\testFile`)

		t.Fatal(err)
	}

	atime, err := time.Parse(time.RFC3339, "2006-01-02T15:04:05Z")
	if err != nil {
		t.Fatal(err)
	}
	mtime, err := time.Parse(time.RFC3339, "2006-03-08T19:32:05Z")
	if err != nil {
		t.Fatal(err)
	}

	err = fs.Chtimes(testDir+`\testFile`, atime, mtime)
	if err != nil {
		t.Fatal(err)
	}

	stat, err := fs.Stat(testDir + `\testFile`)
	if err != nil {
		t.Fatal(err)
	}

	if !stat.ModTime().Equal(mtime) {
		t.Error("unexpected mtime:", stat.ModTime())
	}
}

func TestChmod(t *testing.T) {
	if fs == nil {
		t.Skip()
	}
	testDir := fmt.Sprintf("testDir-%d-TestChmod", os.Getpid())
	err := fs.Mkdir(testDir, 0755)
	if err != nil {
		t.Fatal(err)
	}
	defer fs.RemoveAll(testDir)

	f, err := fs.Create(testDir + `\testFile`)
	if err != nil {
		t.Fatal(err)
	}
	defer fs.Remove(testDir + `\testFile`)
	defer f.Close()

	stat, err := f.Stat()
	if err != nil {
		t.Fatal(err)
	}
	if stat.Mode() != 0666 {
		t.Error("unexpected mode:", stat.Mode())
	}
	err = f.Chmod(0444)
	if err != nil {
		t.Fatal(err)
	}
	stat, err = f.Stat()
	if err != nil {
		t.Fatal(err)
	}
	if stat.Mode() != 0444 {
		t.Error("unexpected mode:", stat.Mode())
	}
}

func TestListSharenames(t *testing.T) {
	if session == nil {
		t.Skip()
	}
	names, err := session.ListSharenames()
	if err != nil {
		t.Fatal(err)
	}
	sort.Strings(names)
	for _, expected := range []string{"IPC$", "tmp", "tmp2"} {
		found := false
		for _, name := range names {
			if name == expected {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("couldn't find share name %s in %v", expected, names)
		}
	}
}

func TestServerSideCopy(t *testing.T) {
	if fs == nil {
		t.Skip()
	}

	testDir := fmt.Sprintf("testDir-%d-TestServerSideCopy", os.Getpid())
	err := fs.Mkdir(testDir, 0755)
	if err != nil {
		t.Fatal(err)
	}
	defer fs.RemoveAll(testDir)

	err = fs.WriteFile(join(testDir, "src.txt"), []byte("hello world!"), 0666)
	if err != nil {
		t.Fatal(err)
	}
	sf, err := fs.Open(join(testDir, "src.txt"))
	if err != nil {
		t.Fatal(err)
	}
	defer sf.Close()

	df, err := fs.Create(join(testDir, "dst.txt"))
	if err != nil {
		t.Fatal(err)
	}
	defer df.Close()

	_, err = io.Copy(df, sf)
	if err != nil {
		t.Error(err)
	}

	bs, err := fs.ReadFile(join(testDir, "dst.txt"))
	if err != nil {
		t.Fatal(err)
	}

	if string(bs) != "hello world!" {
		t.Error("unexpected content")
	}
}

func TestRemoveAll(t *testing.T) {
	if fs == nil {
		t.Skip()
	}

	testDir := fmt.Sprintf("testDir-%d-TestRemoveAll", os.Getpid())
	err := fs.Mkdir(testDir, 0755)
	if err != nil {
		t.Fatal(err)
	}
	err = fs.WriteFile(join(testDir, "hello.txt"), []byte("hello world!"), 0666)
	if err != nil {
		t.Fatal(err)
	}
	err = fs.Mkdir(join(testDir, "hello"), 0755)
	if err != nil {
		t.Fatal(err)
	}
	err = fs.WriteFile(join(testDir, "hello", "hello.txt"), []byte("hello world!"), 0444)
	if err != nil {
		t.Fatal(err)
	}
	err = fs.RemoveAll(testDir)
	if err != nil {
		t.Error(err)
	}
}

func TestContextError(t *testing.T) {
	if session == nil {
		t.Skip()
	}

	ctx, cancel := context.WithCancel(context.Background())

	s := session.WithContext(ctx)
	fs := fs.WithContext(ctx)
	f, err := fs.Open(".")
	if err != nil {
		t.Fatal(err)
	}

	cancel()

	checkError1 := func(op string, err error) {
		if err == nil || err.(*smb2.ContextError).Err != context.Canceled {
			t.Errorf("unexpected context handling: op=%s, type=%T, value=%v", op, err, err)
		}
	}

	checkError2 := func(op string, err error) {
		switch e := err.(type) {
		case *os.PathError:
			err = e.Err.(*smb2.ContextError).Err
			if err != context.Canceled {
				t.Errorf("unexpected context handling: op=%s, type=%T, value=%v", op, err, err)
			}
		case *os.LinkError:
			err = e.Err.(*smb2.ContextError).Err
			if err != context.Canceled {
				t.Errorf("unexpected context handling: op=%s, type=%T, value=%v", op, err, err)
			}
		default:
			t.Errorf("unexpected context handling: op=%s, type=%T, value=%v", op, err, err)
		}
	}

	conn, err := net.Dial(cfg.Transport.Type, fmt.Sprintf("%s:%d", cfg.Transport.Host, cfg.Transport.Port))
	if err != nil {
		panic(err)
	}
	defer conn.Close()

	_, err = dialer.DialContext(ctx, conn)
	checkError1("dialcontext", err)

	_, err = s.Mount("somewhere")
	checkError1("mount", err)
	_, err = s.ListSharenames()
	checkError1("listsharename", err)
	err = s.Logoff()
	checkError1("logoff", err)

	err = fs.Chmod("aaa", 0)
	checkError2("chmod", err)
	err = fs.Chtimes("aaa", time.Time{}, time.Time{})
	checkError2("chtimes", err)
	_, err = fs.Create("aaa")
	checkError2("create", err)
	_, err = fs.Lstat("aaa")
	checkError2("lstat", err)
	err = fs.Mkdir("aaa", 0)
	checkError2("mkdir", err)
	err = fs.MkdirAll("aaa", 0)
	checkError2("mkdirall", err)
	_, err = fs.Open("aaa")
	checkError2("open", err)
	_, err = fs.OpenFile("aaa", 0, 0)
	checkError2("openfile", err)
	_, err = fs.ReadDir("aaa")
	checkError2("readdir", err)
	_, err = fs.ReadFile("aaa")
	checkError2("readfile", err)
	_, err = fs.Readlink("aaa")
	checkError2("readlink", err)
	err = fs.Remove("aaa")
	checkError2("remove", err)
	err = fs.RemoveAll("aaa")
	checkError2("removeall", err)
	err = fs.Rename("aaa", "bbb")
	checkError2("rename", err)
	_, err = fs.Stat("aaa")
	checkError2("stat", err)
	_, err = fs.Statfs("aaa")
	checkError2("statfs", err)
	err = fs.Symlink("aaa", "bbb")
	checkError2("symlink", err)
	err = fs.Truncate("aaa", 0)
	checkError2("truncate", err)
	err = fs.WriteFile("aaa", nil, 0)
	checkError2("writefile", err)
	err = fs.Umount()
	checkError1("umount", err)

	err = f.Chmod(0)
	checkError2("fchmod", err)
	_, err = f.Read(make([]byte, 10))
	checkError2("fread", err)
	_, err = f.ReadAt(make([]byte, 10), 0)
	checkError2("freadat", err)
	_, err = f.ReadFrom(strings.NewReader("aaa"))
	checkError2("freadfrom", err)
	_, err = f.Readdir(-1)
	checkError2("freaddir", err)
	_, err = f.Readdirnames(-1)
	checkError2("freaddirnames", err)
	_, err = f.Seek(1, io.SeekEnd)
	checkError2("fseek", err)
	_, err = f.Stat()
	checkError2("fstat", err)
	_, err = f.Statfs()
	checkError2("fstatfs", err)
	err = f.Sync()
	checkError2("fsync", err)
	err = f.Truncate(1)
	checkError2("ftruncate", err)
	f.Seek(0, io.SeekStart)
	_, err = f.Write([]byte("aa"))
	checkError2("fwrite", err)
	_, err = f.WriteAt([]byte("aa"), 0)
	checkError2("fwriteat", err)
	f.Seek(0, io.SeekStart)
	_, err = f.WriteString("aa")
	checkError2("fwritestring", err)
	f.Seek(0, io.SeekStart)
	_, err = f.WriteTo(bytes.NewBufferString("aaa"))
	checkError2("fwriteto", err)
}

func TestGlob(t *testing.T) {
	if fs == nil {
		t.Skip()
	}

	testDir := fmt.Sprintf("testDir-%d-TestGlob", os.Getpid())
	err := fs.Mkdir(testDir, 0755)
	if err != nil {
		t.Fatal(err)
	}
	defer fs.RemoveAll(testDir)

	for _, dir := range []string{"", "dir1", "dir2", "dir3"} {
		if dir != "" {
			err = fs.Mkdir(join(testDir, dir), 0755)
			if err != nil {
				t.Fatal(err)
			}
		}
		for _, file := range []string{"abc.ext", "ab1.ext", "ab9.ext", "test", "tes"} {
			err = fs.WriteFile(join(testDir, dir, file), []byte("hello world!"), 0666)
			if err != nil {
				t.Fatal(err)
			}
		}
	}

	matches1, err := fs.Glob(join(testDir, "ab[0-9].ext"))
	if err != nil {
		t.Fatal(err)
	}
	expected1 := []string{join(testDir, "ab1.ext"), join(testDir, "ab9.ext")}

	if !reflect.DeepEqual(matches1, expected1) {
		t.Errorf("unexpected matches: %v != %v", matches1, expected1)
	}

	matches2, err := fs.Glob(join(testDir, "tes?"))
	if err != nil {
		t.Fatal(err)
	}
	expected2 := []string{join(testDir, "test")}

	if !reflect.DeepEqual(matches2, expected2) {
		t.Errorf("unexpected matches: %v != %v", matches2, expected2)
	}

	matches3, err := fs.Glob(join(testDir, "dir[0-2]/ab[0-9].ext"))
	if err != nil {
		t.Fatal(err)
	}
	expected3 := []string{join(testDir, "dir1", "ab1.ext"), join(testDir, "dir1", "ab9.ext"), join(testDir, "dir2", "ab1.ext"), join(testDir, "dir2", "ab9.ext")}

	if !reflect.DeepEqual(matches3, expected3) {
		t.Errorf("unexpected matches: %v != %v", matches3, expected3)
	}

	matches4, err := fs.Glob(join(testDir, "*/ab[0-9].ext"))
	if err != nil {
		t.Fatal(err)
	}
	expected4 := []string{join(testDir, "dir1", "ab1.ext"), join(testDir, "dir1", "ab9.ext"), join(testDir, "dir2", "ab1.ext"), join(testDir, "dir2", "ab9.ext"), join(testDir, "dir3", "ab1.ext"), join(testDir, "dir3", "ab9.ext")}

	if !reflect.DeepEqual(matches4, expected4) {
		t.Errorf("unexpected matches: %v != %v", matches4, expected4)
	}

	matches5, err := fs.Glob(join(testDir, "*/abcd"))
	if err != nil {
		t.Fatal(err)
	}
	expected5 := []string{}

	if !reflect.DeepEqual(matches5, expected5) {
		t.Errorf("unexpected matches: %v != %v", matches5, expected5)
	}
}
