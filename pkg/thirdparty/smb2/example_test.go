package smb2_test

import (
	"fmt"
	"io"
	"io/ioutil"
	"net"

	"gopacket/pkg/thirdparty/smb2"
)

func Example() {
	conn, err := net.Dial("tcp", "localhost:445")
	if err != nil {
		panic(err)
	}
	defer conn.Close()

	d := &smb2.Dialer{
		Initiator: &smb2.NTLMInitiator{
			User:     "Guest",
			Password: "",
			Domain:   "MicrosoftAccount",
		},
	}

	c, err := d.Dial(conn)
	if err != nil {
		panic(err)
	}
	defer c.Logoff()

	fs, err := c.Mount(`\\localhost\share`)
	if err != nil {
		panic(err)
	}
	defer fs.Umount()

	f, err := fs.Create("hello.txt")
	if err != nil {
		panic(err)
	}
	defer fs.Remove("hello.txt")
	defer f.Close()

	_, err = f.Write([]byte("Hello world!"))
	if err != nil {
		panic(err)
	}

	_, err = f.Seek(0, io.SeekStart)
	if err != nil {
		panic(err)
	}

	bs, err := ioutil.ReadAll(f)
	if err != nil {
		panic(err)
	}

	fmt.Println(string(bs))

	// Hello world!
}
