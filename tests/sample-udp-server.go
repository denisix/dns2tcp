package main

import (
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"io"
	"golang.org/x/net/dns/dnsmessage"
	"github.com/miekg/dns"
)

var (
	logger = log.New(os.Stdout, "[udp-server] ", log.LstdFlags)

	host = flag.String("host", "127.0.0.1", "host to listen on")
	port = flag.Int("port", 1053, "port to listen on")
)

const (
	packetLen int = 512
)

func main() {
	flag.Parse()

	ip := net.ParseIP(*host)
	listener, err := net.ListenUDP("udp", &net.UDPAddr{IP: ip, Port: *port})
	if err != nil {
		fmt.Println(err)
		return
	}
	defer listener.Close()

	logger.Printf("listening on %s port %d", listener.LocalAddr(), *port)

	buf := make([]byte, packetLen)

	for {
		n, remoteAddr, err := listener.ReadFromUDP(buf)
		if err != nil {
			logger.Fatalf("error during read: %s", err)
		}

		logger.Printf("<%s> %s\n", remoteAddr, buf[:n])

		var m dnsmessage.Message
		err = m.Unpack(buf)
		if err != nil {
			log.Println(err)
			continue
		}
		if len(m.Questions) == 0 {
			continue
		}

		q := m.Questions[0]

		fmt.Printf("[%s] [%s] [%s]\n", q.Name, q.Type, q.Class)

		switch(q.Type) {
			case dnsmessage.TypeA:
				fmt.Printf("== A ==\n")


		}

		//
		conn, _ := net.Dial("tcp", "1.1.1.1:53")

		packed, err := m.Pack()
		if err != nil {
			fmt.Println(err)
			return
		}

		_, err = conn.Write(packed)
		if err != nil {
			fmt.Println(err)
			return
		}

		//for {
		        _, err = conn.Read(buf)
		        if err != nil {
			        if err != io.EOF {
					fmt.Println("read error:", err)
				}
				break
			}
		//	buf = append(buf, tmp[:n]...)
		//}
		defer conn.Close()

		var ret dnsmessage.Message
		err = ret.Unpack(buf)
		if err != nil {
			log.Println(err)
			continue
		}
		if len(ret.Answers) == 0 {
			continue
		}

		a := ret.Answers[0]

		fmt.Printf("ANSWER: %v\n", ret)
		fmt.Printf("ANSWER: %v\n", a)
	}
}
