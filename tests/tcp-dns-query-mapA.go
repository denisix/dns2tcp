package main

import (
	"fmt"
	"net"
	"os"
	"time"
	"errors"
	"github.com/miekg/dns"
)

type recA struct {
	ttl uint32
	ip net.IP
    expires int64
}

type mapKey struct {
    rec		uint16
    domain	string
}

var mapA map[mapKey]recA

// =====================================================================================================
func query(rec uint16, domain string) (recA, error) {
	c := new(dns.Client)
	c.Net = "tcp"
	c.Net = "tcp4"

	var nameserver = "1.1.1.1:53"

	m := &dns.Msg{
		MsgHdr: dns.MsgHdr{
			Authoritative:     false,
			AuthenticatedData: false,
			CheckingDisabled:  false,
			RecursionDesired:  true,
			Opcode:            dns.OpcodeQuery,
		},
		Question: make([]dns.Question, 1),
	}

	co := new(dns.Conn)
	tcp := "tcp"
	var err error
	if co.Conn, err = net.DialTimeout(tcp, nameserver, 2*time.Second); err != nil {
		return recA{}, errors.New("- cant connect over TCP")
	}
	defer co.Close()

	m.Id = dns.Id()
	m.Question[0] = dns.Question{Name: dns.Fqdn(domain), Qtype: rec, Qclass: uint16(dns.ClassINET)}
	co.SetReadDeadline(time.Now().Add(2 * time.Second))
	co.SetWriteDeadline(time.Now().Add(2 * time.Second))

	if err := co.WriteMsg(m); err != nil {
		fmt.Fprintf(os.Stderr, ";; %s\n", err.Error())
		return recA{}, errors.New("- cant sent message")
	}
	r, err := co.ReadMsg()
	if err != nil {
		fmt.Fprintf(os.Stderr, ";; %s\n", err.Error())
		return recA{}, errors.New("- cant read message")
	}
	if r.Id != m.Id {
		return recA{}, errors.New("- Id mismatch")
	}

	for i, _ := range r.Answer {
		fmt.Printf("\n[%v] name[%s]\n", r.Answer[i], r.Answer[i])
		var h = r.Answer[i].Header()
		switch(h.Rrtype) {
			case dns.TypeA:
							mapA recA { ttl: h.Ttl, ip: r.Answer[i].(*dns.A).A }
				break;
			case dns.TypeMX: t = "MX"; break;
			case dns.TypeNS: t = "NS"; break;
			case dns.TypeTXT: t = "TXT"; break;
		}
		fmt.Printf("\nname [%s] type[%s] ttl[%d] val[%s]\n", h.Name, t, h.Ttl, r.Answer[i].(*dns.A).A)
		return recA { ttl: h.Ttl, ip: r.Answer[i].(*dns.A).A }, nil
	}
	return recA{}, errors.New("- empty reply")
}

// =====================================================================================================
func main() {
	query(dns.TypeA, "google.com")
}
