package main

import (
	"fmt"
	"net"
	"time"
	"github.com/miekg/dns"
	"io/ioutil"
	"strings"
	"sync"
	"strconv"
)

const filename = "dns2tcp.conf";

type recA struct {
	ip net.IP
    expires uint32
}

type recNS struct {
	v string
    expires uint32
}

type recCNAME struct {
	v string
    expires uint32
}

type recSOA struct {
	ns string
	mbox string
	serial uint32
	refresh uint32
    retry   uint32
    expires uint32
}

type recPTR struct {
	v string
    expires uint32
}

type recMX struct {
	mx string
	pref uint16
    expires uint32
}

type recTXT struct {
	txt []string
    expires uint32
}

type recSRV struct {
	v string
	prio uint16
    wei  uint16
    port uint16
    expires uint32
}

type recSPF struct {
	txt []string
    expires uint32
}

type REC struct {
	a []recA
	ns []recNS
	cname []recCNAME
	soa []recSOA
	ptr []recPTR
	mx []recMX
	txt []recTXT
	srv []recSRV
	spf []recSPF
	found bool
}

var mapA	= map[string][]recA{}
var mapNS	= map[string][]recNS{}
var mapCNAME= map[string][]recCNAME{}
var mapSOA	= map[string][]recSOA{}
var mapPTR	= map[string][]recPTR{}
var mapMX	= map[string][]recMX{}
var mapTXT	= map[string][]recTXT{}
var mapSRV	= map[string][]recSRV{}
var mapSPF	= map[string][]recSPF{}

var lockA = sync.RWMutex{}
var lockNS = sync.RWMutex{}
var lockCNAME = sync.RWMutex{}
var lockSOA = sync.RWMutex{}
var lockPTR = sync.RWMutex{}
var lockMX = sync.RWMutex{}
var lockTXT = sync.RWMutex{}
var lockSRV = sync.RWMutex{}
var lockSPF = sync.RWMutex{}

var NS []string

var len_NS = 0
var rr_i = 0
var ttl_absent uint32
var retry = 10
var timeout time.Duration
var gc_interval time.Duration

// =====================================================================================================
func remove(s []int, i int) []int {
    s[len(s)-1], s[i] = s[i], s[len(s)-1]
    return s[:len(s)-1]
}

func roundrobin() string {
	if (rr_i >= len_NS -1) {
		rr_i = 0;
	}

	ret := NS[rr_i];
	rr_i++;

	return ret;
}

func query(rec uint16, domain string) REC {
	c := new(dns.Client)
	c.Net = "tcp"
	c.Net = "tcp4"
	var f REC
	var nameserver string


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

	for i := 0; i < retry; i++ {
		nameserver = roundrobin()

		//if (domain == "google.com.") { fmt.Printf("- query for %s to %s\n", domain, nameserver)	}
		if co.Conn, err = net.DialTimeout(tcp, nameserver, timeout); err == nil { break }
		if (i > 0) { // && (domain == "google.com.")) {
			//fmt.Printf("- RETRY %d: query for %s to %s\n", i, domain, nameserver)
			time.Sleep(100000000)
		}
		//fmt.Printf(".")
	}
	if err != nil { return f }

	defer co.Close()

	m.Id = dns.Id()
	m.Question[0] = dns.Question{Name: dns.Fqdn(domain), Qtype: rec, Qclass: uint16(dns.ClassINET)}
	co.SetReadDeadline(time.Now().Add(timeout))
	co.SetWriteDeadline(time.Now().Add(timeout))

	//if (domain == "google.com.") { fmt.Printf("- 1: writing question to %s\n", nameserver) }

	if err := co.WriteMsg(m); err != nil { return f }

	//if (domain == "google.com.") { fmt.Printf("- 2: ok, wrote question to %s\n", nameserver) }

	//fmt.Printf("\n- read msg");
	r, err := co.ReadMsg()
	if err != nil { return f }
	if r.Id != m.Id { return f }
	//fmt.Printf("\n- ok, answer = [%v]", r.Answer);

	//if (domain == "google.com.") { fmt.Printf("- 3: ok, got answer [%v] from %s\n", r.Answer, nameserver) }

	found := false
	unixtime := uint32(time.Now().Unix())
	for i, _ := range r.Answer {
		b := r.Answer[i]

		h := b.Header()
		//if (rec == h.Rrtype) {
			//fmt.Printf("\n- ok, answer ok type=%d", rec);
			found = true
			switch(h.Rrtype) {
				case dns.TypeA:		f.a = append(f.a, recA { ip: b.(*dns.A).A, expires: h.Ttl + unixtime })
									lockA.Lock()
									 mapA[domain] = f.a
									lockA.Unlock()
									break

				case dns.TypeNS:	f.ns = append(f.ns, recNS { v: b.(*dns.NS).Ns, expires: h.Ttl + unixtime })
									lockNS.Lock()
									 mapNS[domain] = f.ns
									lockNS.Unlock()
									break

				case dns.TypeCNAME:	f.cname = append(f.cname, recCNAME { v: b.(*dns.CNAME).Target, expires: h.Ttl + unixtime })
									lockCNAME.Lock()
									 mapCNAME[domain] = f.cname
									lockCNAME.Unlock()
									break

				case dns.TypeSOA:	soa := b.(*dns.SOA);
									f.soa = append(f.soa, recSOA { ns: soa.Ns, mbox: soa.Mbox, serial: soa.Serial, refresh: soa.Refresh, retry: soa.Retry, expires: h.Ttl + unixtime })
									lockSOA.Lock()
									 mapSOA[domain] = f.soa
									lockSOA.Unlock()
									break

				case dns.TypePTR:	f.ptr = append(f.ptr, recPTR { v: b.(*dns.PTR).Ptr, expires: h.Ttl + unixtime })
									lockPTR.Lock()
									 mapPTR[domain] = f.ptr
									lockPTR.Unlock()
									break

				case dns.TypeMX:	f.mx = append(f.mx, recMX { mx: b.(*dns.MX).Mx, pref: b.(*dns.MX).Preference, expires: h.Ttl + unixtime })
									lockMX.Lock()
									 mapMX[domain] = f.mx
									lockMX.Unlock()
									break

				case dns.TypeTXT:	f.txt = append(f.txt, recTXT { txt: b.(*dns.TXT).Txt, expires: h.Ttl + unixtime })
									lockTXT.Lock()
									 mapTXT[domain] = f.txt
									lockTXT.Unlock()
									break

				case dns.TypeSRV:	srv := b.(*dns.SRV)
									f.srv = append(f.srv, recSRV { v: srv.Target, prio: srv.Priority, wei: srv.Weight, port: srv.Port, expires: h.Ttl + unixtime })
									lockSRV.Lock()
									 mapSRV[domain] = f.srv
									lockSRV.Unlock()
									break

				case dns.TypeSPF:	f.spf = append(f.spf, recSPF { txt: b.(*dns.SPF).Txt, expires: h.Ttl + unixtime })
									lockSPF.Lock()
									 mapSPF[domain] = f.spf
									lockSPF.Unlock()
									break
			}
			//fmt.Printf("\nname [%s] ttl[%d] val[%s]\n", h.Name, h.Ttl, r.Answer[i].(*dns.A).A);
			//return recA { ttl: h.Ttl, ip: r.Answer[i].(*dns.A).A }, nil
		//}
	}

	if (!found) {
		//fmt.Println("\n- answer empty");
		switch(rec) {
			case dns.TypeA:		lockA.Lock()
								 mapA[domain]	= []recA	{{ expires: ttl_absent + unixtime }}
								lockA.Unlock()
								break

			case dns.TypeNS:	lockNS.Lock()
								 mapNS[domain]	= []recNS	{{ expires: ttl_absent + unixtime }}
								lockNS.Unlock()
								break

			case dns.TypeCNAME:	lockCNAME.Lock()
								 mapCNAME[domain]= []recCNAME{{ expires: ttl_absent + unixtime }}
								lockCNAME.Unlock()
								break

			case dns.TypeSOA:	lockSOA.Lock()
								 mapSOA[domain]	= []recSOA	{{ expires: ttl_absent + unixtime }}
								lockSOA.Unlock()
								break

			case dns.TypePTR:	lockPTR.Lock()
							     mapPTR[domain]	= []recPTR	{{ expires: ttl_absent + unixtime }}
								lockPTR.Unlock()
								break

			case dns.TypeMX:	lockMX.Lock()
								 mapMX[domain]	= []recMX	{{ expires: ttl_absent + unixtime }}
								lockMX.Unlock()
								break

			case dns.TypeTXT:	lockTXT.Lock()
								 mapTXT[domain]	= []recTXT	{{ expires: ttl_absent + unixtime }}
								lockTXT.Unlock()
								break

			case dns.TypeSRV:	lockSRV.Lock()
								 mapSRV[domain]	= []recSRV	{{ expires: ttl_absent + unixtime }}
								lockSRV.Unlock()
								break

			case dns.TypeSPF:	lockSPF.Lock()
								 mapSPF[domain]	= []recSPF	{{ expires: ttl_absent + unixtime }}
								lockSPF.Unlock()
								break
		}
	}
	f.found = found

	return f
}

// =====================================================================================================
type handleReq struct{}
func (this *handleReq) ServeDNS(w dns.ResponseWriter, r *dns.Msg) {
	//clientIp := w.RemoteAddr().(*net.UDPAddr).IP
	//fmt.Printf("- req from %s\n", clientIp)
	m := new(dns.Msg)
	m.SetReply(r)
	m.Compress = false
	m.Authoritative = true
	unixtime := uint32(time.Now().Unix())

	if (r.Opcode == dns.OpcodeQuery) {
		//fmt.Printf("- req opcode OK\n")
		domain := strings.ToLower(m.Question[0].Name)
		//fmt.Printf("- req domain [%s]\n", domain)
		ok := false

		//fmt.Printf("- req type = [%v+]\n", r.Question[0].Qtype)

		switch r.Question[0].Qtype {

			// A ---------------------------------------------------------------------------------------------------------------------------------------------
			case dns.TypeA:
				var rec []recA

				lockA.Lock()
				if rec, ok = mapA[domain]; ok { // found
					lockA.Unlock();
					//fmt.Printf("- domain [%s] found in map => %v\n", domain, rec)
					//rec = a
				} else {
					lockA.Unlock();

					//fmt.Printf("- domain [%s] not found in map, query..\n", domain)
					f := query(dns.TypeA, domain)
					if (f.found) {
						//fmt.Printf("\nquery found => %+v \t MAP = %+v\n\n", f, f.a)
						rec = f.a
						//found = true
					}
				}

				l := len(rec)
				if (l > 0) {
					//fmt.Printf("- finally domain [%s] found, answer.\n", domain)
					//fmt.Printf("rec => %+v\n\n", rec)
					for i := 0; i < l; i++ {
						m.Answer = append(m.Answer, &dns.A {
							Hdr: dns.RR_Header{ Name: domain, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: rec[i].expires - unixtime },
							A: rec[i].ip,
						})
					}

				} else { // try to check CNAME if exists

					var rec []recCNAME;
					lockCNAME.Lock();
					if rec, ok = mapCNAME[domain]; ok {
						lockCNAME.Unlock();
					} else {
						lockCNAME.Unlock();
						f := query(dns.TypeCNAME, domain)
						if (f.found) { rec = f.cname }
					}

					l := len(rec)
					if (l > 0) {
						for i := 0; i < l; i++ {
							m.Answer = append(m.Answer, &dns.CNAME {
								Hdr: dns.RR_Header{ Name: domain, Rrtype: dns.TypeCNAME, Class: dns.ClassINET, Ttl: rec[i].expires - unixtime },
								Target: rec[i].v,
							})
						}
					}
				}
				break;

			// CNAME ---------------------------------------------------------------------------------------------------------------------------------------------
			case dns.TypeCNAME:
				var rec []recCNAME;
				lockCNAME.Lock();
				if rec, ok = mapCNAME[domain]; ok {
					lockCNAME.Unlock();
				} else {
					lockCNAME.Unlock();
					f := query(dns.TypeCNAME, domain)
					if (f.found) { rec = f.cname }
				}

				l := len(rec)
				if (l > 0) {
					for i := 0; i < l; i++ {
						m.Answer = append(m.Answer, &dns.CNAME {
							Hdr: dns.RR_Header{ Name: domain, Rrtype: dns.TypeCNAME, Class: dns.ClassINET, Ttl: rec[i].expires - unixtime },
							Target: rec[i].v,
						})
					}
				}
				break;

			// MX ---------------------------------------------------------------------------------------------------------------------------------------------
			case dns.TypeMX:
				var rec []recMX;
				lockMX.Lock();
				if rec, ok = mapMX[domain]; ok {
					lockMX.Unlock();
				} else {
					lockMX.Unlock();
					f := query(dns.TypeMX, domain)
					if (f.found) { rec = f.mx }
				}

				l := len(rec)
				if (l > 0) {
					for i := 0; i < l; i++ {
						m.Answer = append(m.Answer, &dns.MX {
							Hdr: dns.RR_Header{ Name: domain, Rrtype: dns.TypeMX, Class: dns.ClassINET, Ttl: rec[i].expires - unixtime },
							Mx: rec[i].mx,
							Preference: rec[i].pref,
						})
					}
				}
				break;

			// NS ---------------------------------------------------------------------------------------------------------------------------------------------
			case dns.TypeNS:
				var rec []recNS;
				lockNS.Lock();
				if rec, ok = mapNS[domain]; ok {
					lockNS.Unlock();
				} else {
					lockNS.Unlock();
					f := query(dns.TypeNS, domain)
					if (f.found) { rec = f.ns }
				}

				l := len(rec)
				if (l > 0) {
					for i := 0; i < l; i++ {
						m.Answer = append(m.Answer, &dns.NS {
							Hdr: dns.RR_Header{ Name: domain, Rrtype: dns.TypeNS, Class: dns.ClassINET, Ttl: rec[i].expires - unixtime },
							Ns: rec[i].v,
						})
					}
				}
				break;


			// SOA ---------------------------------------------------------------------------------------------------------------------------------------------
			case dns.TypeSOA:
				var rec []recSOA;
				lockSOA.Lock();
				if rec, ok = mapSOA[domain]; ok {
					lockSOA.Unlock();
				} else {
					lockSOA.Unlock();
					f := query(dns.TypeSOA, domain)
					if (f.found) { rec = f.soa }
				}

				l := len(rec)
				if (l > 0) {
					for i := 0; i < l; i++ {
						m.Answer = append(m.Answer, &dns.SOA {
							Hdr: dns.RR_Header{ Name: domain, Rrtype: dns.TypeSOA, Class: dns.ClassINET, Ttl: rec[i].expires - unixtime },
							Ns: rec[i].ns,
							Mbox: rec[i].mbox,
							Serial: rec[i].serial,
							Refresh: rec[i].refresh,
							Retry: rec[i].retry,
						})
					}
				}
				break;

			// PTR ---------------------------------------------------------------------------------------------------------------------------------------------
			case dns.TypePTR:
				var rec []recPTR;
				lockPTR.Lock();
				if rec, ok = mapPTR[domain]; ok {
					lockPTR.Unlock();
				} else {
					lockPTR.Unlock();
					f := query(dns.TypePTR, domain)
					if (f.found) { rec = f.ptr }
				}

				l := len(rec)
				if (l > 0) {
					for i := 0; i < l; i++ {
						m.Answer = append(m.Answer, &dns.PTR {
							Hdr: dns.RR_Header{ Name: domain, Rrtype: dns.TypePTR, Class: dns.ClassINET, Ttl: rec[i].expires - unixtime },
							Ptr: rec[i].v,
						})
					}
				}
				break;


			// TXT ---------------------------------------------------------------------------------------------------------------------------------------------
			case dns.TypeTXT:
				var rec []recTXT;
				lockTXT.Lock();
				if rec, ok = mapTXT[domain]; ok {
					lockTXT.Unlock();
				} else {
					lockTXT.Unlock();
					f := query(dns.TypeTXT, domain)
					if (f.found) { rec = f.txt }
				}

				l := len(rec)
				if (l > 0) {
					for i := 0; i < l; i++ {
						m.Answer = append(m.Answer, &dns.TXT {
							Hdr: dns.RR_Header{ Name: domain, Rrtype: dns.TypeTXT, Class: dns.ClassINET, Ttl: rec[i].expires - unixtime },
							Txt: rec[i].txt,
						})
					}
				}
				break;

			// SRV ---------------------------------------------------------------------------------------------------------------------------------------------
			case dns.TypeSRV:
				var rec []recSRV;
				lockSRV.Lock();
				if rec, ok = mapSRV[domain]; ok {
					lockSRV.Unlock();
				} else {
					lockSRV.Unlock();
					f := query(dns.TypeSRV, domain)
					if (f.found) { rec = f.srv }
				}

				l := len(rec)
				if (l > 0) {
					for i := 0; i < l; i++ {
						m.Answer = append(m.Answer, &dns.SRV {
							Hdr: dns.RR_Header{ Name: domain, Rrtype: dns.TypeSRV, Class: dns.ClassINET, Ttl: rec[i].expires - unixtime },
							Target: rec[i].v,
							Priority: rec[i].prio,
							Weight: rec[i].wei,
							Port: rec[i].port,
						})
					}
				}
				break;

			// SPF ---------------------------------------------------------------------------------------------------------------------------------------------
			case dns.TypeSPF:
				var rec []recSPF;
				lockSPF.Lock();
				if rec, ok = mapSPF[domain]; ok {
					lockSPF.Unlock();
				} else {
					lockSPF.Unlock();
					f := query(dns.TypeSPF, domain)
					if (f.found) { rec = f.spf }
				}

				l := len(rec)
				if (l > 0) {
					for i := 0; i < l; i++ {
						m.Answer = append(m.Answer, &dns.SPF {
							Hdr: dns.RR_Header{ Name: domain, Rrtype: dns.TypeSPF, Class: dns.ClassINET, Ttl: rec[i].expires - unixtime },
							Txt: rec[i].txt,
						})
					}
				}
				break;

			// ANY ---------------------------------------------------------------------------------------------------------------------------------------------
			case dns.TypeANY:

				// try A
				var rec []recA;
				lockA.Lock();
				if rec, ok = mapA[domain]; ok {
					lockA.Unlock();
				} else {
					lockA.Unlock();
					f := query(dns.TypeA, domain)
					if (f.found) { rec = f.a }
				}

				l := len(rec)
				if (l > 0) {
					for i := 0; i < l; i++ {
						m.Answer = append(m.Answer, &dns.A {
							Hdr: dns.RR_Header{ Name: domain, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: rec[i].expires - unixtime },
							A: rec[i].ip,
						})
					}
					break;
				}

				// try CNAME
				var recC []recCNAME;
				lockCNAME.Lock();
				if recC, ok = mapCNAME[domain]; ok {
					lockCNAME.Unlock();
				} else {
					lockCNAME.Unlock();
					f := query(dns.TypeCNAME, domain)
					if (f.found) { recC = f.cname }
				}

				l = len(recC)
				if (l > 0) {
					for i := 0; i < l; i++ {
						m.Answer = append(m.Answer, &dns.CNAME {
							Hdr: dns.RR_Header{ Name: domain, Rrtype: dns.TypeCNAME, Class: dns.ClassINET, Ttl: recC[i].expires - unixtime },
							Target: recC[i].v,
						})
					}
					break;
				}

				// try MX
				var recM []recMX;
				lockMX.Lock();
				if recM, ok = mapMX[domain]; ok {
					lockMX.Unlock();
				} else {
					lockMX.Unlock();
					f := query(dns.TypeMX, domain)
					if (f.found) { recM = f.mx }
				}

				l = len(recM)
				if (l > 0) {
					for i := 0; i < l; i++ {
						m.Answer = append(m.Answer, &dns.MX {
							Hdr: dns.RR_Header{ Name: domain, Rrtype: dns.TypeMX, Class: dns.ClassINET, Ttl: recM[i].expires - unixtime },
							Mx: recM[i].mx,
							Preference: recM[i].pref,
						})
					}
				}
				break;

		}
	}

	w.WriteMsg(m)
}

func garbageCollector() {
	for {
		time.Sleep(gc_interval)
		//fmt.Println("- GC::Sepuha!")

		unixtime := uint32(time.Now().Unix())

		//lockA.RLock();
        fmt.Printf("- A %d\tNS %d\tCNAME %d\tSOA %d\tPTR %d\tMX %d\tTXT %d\tSRV %d\tSPF %d\n", 
			len(mapA),
			len(mapNS),
			len(mapCNAME),
			len(mapSOA),
			len(mapPTR),
			len(mapMX),
			len(mapTXT),
			len(mapSRV),
			len(mapSPF))

		// A ---------------------------------------------------------------------------------------------
        lockA.Lock();
		for x, _ := range mapA {

            l := len(mapA[x]);
            i := 0;
            //fmt.Printf("- x=%s, i=%d, l=%d\n", x, i, l)

            for i < l {
                //fmt.Printf("- x=%s, i=%d, l=%d\n", x, i, l)
                //fmt.Printf("\t exp = %d\n", mapA[x][i].expires-unixtime)

                if mapA[x][i].expires < unixtime {
                    l = len(mapA[x])
					if l > 0 {
						//lockA.Lock();
						mapA[x][l-1], mapA[x][i] = mapA[x][i], mapA[x][l-1]
						mapA[x] = mapA[x][:l-1]
						//lockA.Unlock();
						l--
					}
                }

                i++
                //mapA[x] = append(mapA[x][:i], mapA[x][i+1:]...)
                //fmt.Println("- rr: ");
                //fmt.Println(mapA)

                if l < 0 {
                    break
                }
            }

			if l <= 0 {
				//lockA.Lock();
				delete(mapA, x);
				//lockA.Unlock();
			}

			// index is the index where we are
			// element is the element from someSlice for where we are

		}
        lockA.Unlock();


		// NS ---------------------------------------------------------------------------------------------
        lockNS.Lock();
		for x, _ := range mapNS {
            l := len(mapNS[x]);
            i := 0;
            for i < l {
                if mapNS[x][i].expires < unixtime {
                    l = len(mapNS[x])
					if l > 0 {
						mapNS[x][l-1], mapNS[x][i] = mapNS[x][i], mapNS[x][l-1]
						mapNS[x] = mapNS[x][:l-1]
						l--
					}
                }
                i++
                if l < 0 { break }
            }
			if l <= 0 { delete(mapNS, x); }
		}
        lockNS.Unlock();

		// CNAME ---------------------------------------------------------------------------------------------
        lockCNAME.Lock();
		for x, _ := range mapCNAME {
            l := len(mapCNAME[x]);
            i := 0;
            for i < l {
                if mapCNAME[x][i].expires < unixtime {
                    l = len(mapCNAME[x])
					if l > 0 {
						mapCNAME[x][l-1], mapCNAME[x][i] = mapCNAME[x][i], mapCNAME[x][l-1]
						mapCNAME[x] = mapCNAME[x][:l-1]
						l--
					}
                }
                i++
                if l < 0 { break }
            }
			if l <= 0 { delete(mapCNAME, x); }
		}
        lockCNAME.Unlock();

		// SOA ---------------------------------------------------------------------------------------------
        lockSOA.Lock();
		for x, _ := range mapSOA {
            l := len(mapSOA[x]);
            i := 0;
            for i < l {
                if mapSOA[x][i].expires < unixtime {
                    l = len(mapSOA[x])
					if l > 0 {
						mapSOA[x][l-1], mapSOA[x][i] = mapSOA[x][i], mapSOA[x][l-1]
						mapSOA[x] = mapSOA[x][:l-1]
						l--
					}
                }
                i++
                if l < 0 { break }
            }
			if l <= 0 { delete(mapSOA, x); }
		}
        lockSOA.Unlock();

		// PTR ---------------------------------------------------------------------------------------------
        lockPTR.Lock();
		for x, _ := range mapPTR {
            l := len(mapPTR[x]);
            i := 0;
            for i < l {
                if mapPTR[x][i].expires < unixtime {
                    l = len(mapPTR[x])
					if l > 0 {
						mapPTR[x][l-1], mapPTR[x][i] = mapPTR[x][i], mapPTR[x][l-1]
						mapPTR[x] = mapPTR[x][:l-1]
						l--
					}
                }
                i++
                if l < 0 { break }
            }
			if l <= 0 { delete(mapPTR, x); }
		}
        lockPTR.Unlock();

		// MX ---------------------------------------------------------------------------------------------
        lockMX.Lock();
		for x, _ := range mapMX {
            l := len(mapMX[x]);
            i := 0;
            for i < l {
                if mapMX[x][i].expires < unixtime {
                    l = len(mapMX[x])
					if l > 0 {
						mapMX[x][l-1], mapMX[x][i] = mapMX[x][i], mapMX[x][l-1]
						mapMX[x] = mapMX[x][:l-1]
						l--
					}
                }
                i++
                if l < 0 { break }
            }
			if l <= 0 { delete(mapMX, x); }
		}
        lockMX.Unlock();

		// MX ---------------------------------------------------------------------------------------------
        lockMX.Lock();
		for x, _ := range mapMX {
            l := len(mapMX[x]);
            i := 0;
            for i < l {
                if mapMX[x][i].expires < unixtime {
                    l = len(mapMX[x])
					if l > 0 {
						mapMX[x][l-1], mapMX[x][i] = mapMX[x][i], mapMX[x][l-1]
						mapMX[x] = mapMX[x][:l-1]
						l--
					}
                }
                i++
                if l < 0 { break }
            }
			if l <= 0 { delete(mapMX, x); }
		}
        lockMX.Unlock();

		// TXT ---------------------------------------------------------------------------------------------
        lockTXT.Lock();
		for x, _ := range mapTXT {
            l := len(mapTXT[x]);
            i := 0;
            for i < l {
                if mapTXT[x][i].expires < unixtime {
                    l = len(mapTXT[x])
					if l > 0 {
						mapTXT[x][l-1], mapTXT[x][i] = mapTXT[x][i], mapTXT[x][l-1]
						mapTXT[x] = mapTXT[x][:l-1]
						l--
					}
                }
                i++
                if l < 0 { break }
            }
			if l <= 0 { delete(mapTXT, x); }
		}
        lockTXT.Unlock();

		// SRV ---------------------------------------------------------------------------------------------
        lockSRV.Lock();
		for x, _ := range mapSRV {
            l := len(mapSRV[x]);
            i := 0;
            for i < l {
                if mapSRV[x][i].expires < unixtime {
                    l = len(mapSRV[x])
					if l > 0 {
						mapSRV[x][l-1], mapSRV[x][i] = mapSRV[x][i], mapSRV[x][l-1]
						mapSRV[x] = mapSRV[x][:l-1]
						l--
					}
                }
                i++
                if l < 0 { break }
            }
			if l <= 0 { delete(mapSRV, x); }
		}
        lockSRV.Unlock();

		// SPF ---------------------------------------------------------------------------------------------
        lockSPF.Lock();
		for x, _ := range mapSPF {
            l := len(mapSPF[x]);
            i := 0;
            for i < l {
                if mapSPF[x][i].expires < unixtime {
                    l = len(mapSPF[x])
					if l > 0 {
						mapSPF[x][l-1], mapSPF[x][i] = mapSPF[x][i], mapSPF[x][l-1]
						mapSPF[x] = mapSPF[x][:l-1]
						l--
					}
                }
                i++
                if l < 0 { break }
            }
			if l <= 0 { delete(mapSPF, x); }
		}
        lockSPF.Unlock();

	}
}
// =====================================================================================================
func main() {

	bindTo := "127.0.0.1:8383"
	ttl_absent = 7200
	timeout = 5*time.Second
	gc_interval = 1800*time.Second

	// loading config file
	data, err := ioutil.ReadFile(filename)
	if err != nil {
		fmt.Printf("- Cannot read config file: %s\n ", err.Error())
	}

	// parsing config
	fmt.Printf("- Loading configuration..\n")
	linesConf := strings.Split(string(data), "\n")
	for _, line := range linesConf {
		//fmt.Printf("- line [%s]\n", line)

		// nameservers loading
		if (strings.Index(line, "ns ") == 0) {
			NS = append(NS, strings.Split(line, " ")[1])
		}

		// bind to
		if (strings.Index(line, "bind ") == 0) {
			bindTo = strings.Split(line, " ")[1]
		}

		// ttl-absent
		if (strings.Index(line, "ttl-absent ") == 0) {
			ttl, err := strconv.Atoi(strings.Split(line, " ")[1])
			if err == nil {
				ttl_absent = uint32(ttl)
			}
		}

		// timeout
		if (strings.Index(line, "timeout ") == 0) {
			sec, err := strconv.Atoi(strings.Split(line, " ")[1])
			if err == nil {
				timeout = time.Second * time.Duration(sec)
			}
		}

		// gc-interval
		if (strings.Index(line, "gc-interval ") == 0) {
			sec, err := strconv.Atoi(strings.Split(line, " ")[1])
			if err == nil {
				gc_interval = time.Second * time.Duration(sec)
			}
		}

		// retry
		if (strings.Index(line, "retry ") == 0) {
			retry, err = strconv.Atoi(strings.Split(line, " ")[1])
			if err != nil { retry = 10 }
		}
	}
	len_NS = len(NS)

	fmt.Printf("- Done, using:\n\t- bind to: %s\n\t- ttl absent: %d\n\t- tcp timeout: %d sec\n\t- retry cnt: %d\n\t- garbage collector interval: %d sec\n\t- NSes: %v\n\n", bindTo, ttl_absent, timeout/1000000000, retry, gc_interval/1000000000, NS)

	// starting garbage collector
	go garbageCollector()

	// starting DNS server
	fmt.Printf("- Starting DNS server, binding to %s\n", bindTo)
	serv := &dns.Server{Addr: bindTo, Net: "udp"}
	serv.Handler = &handleReq{}
	/*
	fmt.Printf("rr => %s\n", roundrobin())
	fmt.Printf("rr => %s\n", roundrobin())
	fmt.Printf("rr => %s\n", roundrobin())
	fmt.Printf("rr => %s\n", roundrobin())
	fmt.Printf("rr => %s\n", roundrobin())
	fmt.Printf("rr => %s\n", roundrobin())
	*/

	// checking
	err = serv.ListenAndServe()
	defer serv.Shutdown()
	if err != nil {
		fmt.Printf("- Failed to start server: %s\n ", err.Error())
	}
}
