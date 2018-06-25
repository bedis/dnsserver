package main

/* Code inspired by https://gist.github.com/walm/0d67b4fb2d5daf3edd4fad3e13b162cb */

import (
	"fmt"
	"log"
	"strconv"

	"github.com/miekg/dns"
)

type Record string
type RecordList map[string]Record
type srvRecord struct {
	Priority string
	Weight string
	Port string
	Target string
}
type SrvRecordList []srvRecord


var domain string = "tld."
var port int = 5300
var recordList RecordList = RecordList{
	"A1.tld.": "192.168.0.1",
	"A2.tld.": "192.168.0.2",
	"A3.tld.": "192.168.0.3",
	"A4.tld.": "192.168.0.4",
}
var srvRecordList = map[string]SrvRecordList{
	"_http._tcp.srv.tld.": SrvRecordList{
		{"5", "500", "80", "A1.tld."},
		{"5", "500", "80", "A2.tld."},
		{"5", "500", "80", "A3.tld."},
		{"5", "500", "80", "A4.tld."},
	},
}

func parseQuery(m *dns.Msg) {
	for _, q := range m.Question {
		log.Printf("Query %d for %s\n", m.Id, q.Name)
		switch q.Qtype {
		case dns.TypeA:
			ip := recordList[q.Name]
			if ip != "" {
				rr, err := dns.NewRR(fmt.Sprintf("%s A %s", q.Name, ip))
				if err == nil {
					m.Answer = append(m.Answer, rr)
				}
			}
		case dns.TypeSRV:
			srvs := srvRecordList[q.Name]
			if len(srvs) < 1 {
				goto out
			}

			for _, srv := range srvs {
				if srv.Target != "" {
					rr, err := dns.NewRR(fmt.Sprintf("%s IN SRV %s %s %s %s", q.Name, srv.Priority, srv.Weight, srv.Port, srv.Target))
					if err == nil {
						m.Answer = append(m.Answer, rr)
					}
					ip := recordList[srv.Target]
					rr, err = dns.NewRR(fmt.Sprintf("%s A %s", srv.Target, ip))
					if err == nil {
						m.Extra = append(m.Extra, rr)
					}
				}
			}
		default:
			log.Printf("Qtype not supported yet: %+v\n", q.Qtype)
		}
	}
 out:
	return
}

func handleDnsRequest(w dns.ResponseWriter, r *dns.Msg) {
	m := new(dns.Msg)
	m.SetReply(r)
	m.Compress = false

	switch r.Opcode {
	case dns.OpcodeQuery:
		parseQuery(m)
	}

	w.WriteMsg(m)
}

func main() {
	// attach request handler func
	dns.HandleFunc(domain, handleDnsRequest)

	// start server
	server := &dns.Server{Addr: ":" + strconv.Itoa(port), Net: "udp"}
	log.Printf("Starting at %d\n", port)
	err := server.ListenAndServe()
	defer server.Shutdown()
	if err != nil {
		log.Fatalf("Failed to start server: %s\n ", err.Error())
	}
}
