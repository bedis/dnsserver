package main

/* Code inspired by https://gist.github.com/walm/0d67b4fb2d5daf3edd4fad3e13b162cb */

import (
	"fmt"
	"io/ioutil"
	"log"
	"math/rand"
	"strconv"
	"time"

	"github.com/miekg/dns"
	"gopkg.in/yaml.v2"
)

type Record string
type RecordList map[string]Record
type srvRecord struct {
	Priority string   `yaml:"priority"`
	Weight string     `yaml:"weight"`
	Port string       `yaml:"port"`
	Target string     `yaml:"target"`
}
type SrvRecordList []srvRecord

type conf struct {
	Debug bool                   `yaml:"debug"`
	Domain string                `yaml:"domain"`
	Port int                     `yaml:"port"`
	Srv map[string]SrvRecordList `yaml:"srv"`
	A map[string]string          `yaml:"A"`
}


func (self SrvRecordList) Randomize() (out SrvRecordList) {
	if len(self) == 0 {
		return SrvRecordList{}
	}

	r := rand.New(rand.NewSource(time.Now().Unix()))
	out = make([]srvRecord, len(self))
	perm := r.Perm(len(self))
	for i, randIndex := range perm {
		out[i] = self[randIndex]
	}
	return out
}

func parseQuery(m *dns.Msg, c *conf) {
	for _, q := range m.Question {
		log.Printf("Query %d for %s\n", m.Id, q.Name)
		switch q.Qtype {
		case dns.TypeA:
			ip := c.A[q.Name]
			if ip != "" {
				rr, err := dns.NewRR(fmt.Sprintf("%s A %s", q.Name, ip))
				if err == nil {
					m.Answer = append(m.Answer, rr)
				}
			}
		case dns.TypeSRV:
			srvs := c.Srv[q.Name]
			if len(srvs) < 1 {
				goto out
			}

			for _, srv := range srvs.Randomize() {
				if srv.Target != "" {
					rr, err := dns.NewRR(fmt.Sprintf("%s IN SRV %s %s %s %s", q.Name, srv.Priority, srv.Weight, srv.Port, srv.Target))
					if err == nil {
						m.Answer = append(m.Answer, rr)
					}
					ip := c.A[srv.Target]
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

func handleDnsRequest(w dns.ResponseWriter, r *dns.Msg, c *conf) {
	m := new(dns.Msg)
	m.SetReply(r)
	m.Compress = false

	switch r.Opcode {
	case dns.OpcodeQuery:
		parseQuery(m, c)
	}

	w.WriteMsg(m)
}

func (c *conf) loadConf() (*conf) {
	// load conf file
	yamlFile, err := ioutil.ReadFile("conf.yaml")
	if err != nil {
		log.Printf("yamlFile.Get err   #%v ", err)
	}
	err = yaml.Unmarshal(yamlFile, c)
	if err != nil {
		log.Fatalf("Unmarshal: %v", err)
	}

	return c
}

func main() {
	var c conf
	c.loadConf()
	if (c.Debug) {
		fmt.Printf("%#v\n", c)
	}

	// attach request handler func
	dns.HandleFunc(c.Domain, func(w dns.ResponseWriter, r *dns.Msg) {handleDnsRequest(w, r, &c)} )

	// start server
	server := &dns.Server{Addr: ":" + strconv.Itoa(c.Port), Net: "udp"}
	log.Printf("Starting at %d\n", c.Port)
	err := server.ListenAndServe()
	defer server.Shutdown()
	if err != nil {
		log.Fatalf("Failed to start server: %s\n ", err.Error())
	}
}
