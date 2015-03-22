package main

import (
	"flag"
	"net"
	"io"
	"fmt"
)

const (
	SOCKET_NAME string = "/tmp/zonecut.sock"
)

func main() {
	flag.Parse()
	if flag.NArg() != 2 && flag.NArg() != 1 {
		panic("Usage: program domain [qtype as a number] ...")
	}
	c, err := net.Dial("unix", "@"+SOCKET_NAME)
	if err != nil {
		panic(err)
	}
	defer c.Close()
	domain := flag.Arg(0)
	qtype := "1" // A record (IPv4 address)
	if flag.NArg() != 1 {
		qtype = flag.Arg(1)
	}
	_, err = c.Write([]byte(domain + "\000" + qtype))
	if err != nil {
		panic(err)
	}
	buf := make([]byte, 512)
	nr, err := c.Read(buf)
	if err != nil {
		if err != io.EOF {
			panic(err)
		}
	}
	data := buf[0:nr]
	fmt.Printf("Got \"%s\"\n", string(data))
}
