package main

import (
	"errors"
	"log"
	"net"
	"strings"

	"golang.org/x/net/dns/dnsmessage"
)

func () main {

	var err error
	s.conn, err = net.ListenUDP("udp", &net.UDPAddr{Port: udpPort})
	if err != nil {
		log.Fatal(err)
	}
	defer s.conn.Close()

	

}
