package main

/* Code inspired by https://gist.github.com/walm/0d67b4fb2d5daf3edd4fad3e13b162cb */

import (
	"fmt"
	"io/ioutil"
	"log"
	"math/rand"
	"strconv"
	"strings"
	"time"

	"github.com/fsnotify/fsnotify"
	"github.com/miekg/dns"
	"gopkg.in/yaml.v2"
)

const (
	defaultTtl = 3600
	nbChaosErrors = 2
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
	Ttl uint32                   `yaml:"ttl"`
	Chaos int                    `yaml:"chaos"`
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
	// adding some chaos errors
	if c.Chaos > 0 {
		if rand.Intn(100 * nbChaosErrors) <= c.Chaos {
			log.Printf("[CHAOS]: query ignored\n")
			return
		}
	}
	for _, q := range m.Question {
		log.Printf("Query %d for %s\n", m.Id, q.Name)
		switch q.Qtype {
		case dns.TypeA:
			// adding some chaos errors
			if c.Chaos > 0 {
				if rand.Intn(100 * nbChaosErrors) <= c.Chaos {
					log.Printf("[CHAOS]: delay added before processing the query (10s)\n")
					time.Sleep(10 * time.Second)
				}
			}
			ips := strings.Fields(c.A[q.Name])
			log.Printf("IP: %+v\n", ips);
			if len(ips) > 0 {
				for _, ip := range ips {
					rr, err := dns.NewRR(fmt.Sprintf("%s A %s", q.Name, ip))
					rr.Header().Ttl = c.Ttl
					if err == nil {
						m.Answer = append(m.Answer, rr)
					}
				}
			} else {
				m.SetRcode(m, dns.RcodeNameError)
				goto out
			}
		case dns.TypeSRV:
			srvs := c.Srv[q.Name]
			if len(srvs) < 1 {
				m.SetRcode(m, dns.RcodeNameError)
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
	c.Ttl = 0
	yamlFile, err := ioutil.ReadFile("conf/conf.yaml")
	if err != nil {
		log.Printf("yamlFile.Get err   #%v ", err)
	}
	err = yaml.Unmarshal(yamlFile, c)
	if err != nil {
		log.Fatalf("Unmarshal: %v", err)
	}

	if c.Ttl == 0 {
		c.Ttl = defaultTtl
	}

	return c
}

var c conf

func init() {
	c.loadConf()
	if (c.Debug) {
		fmt.Printf("%#v\n", c)
	}

	rand.Seed(time.Now().UnixNano())
}

func main() {
	// attach request handler func
	dns.HandleFunc(c.Domain, func(w dns.ResponseWriter, r *dns.Msg) {handleDnsRequest(w, r, &c)} )

	// start server
	server := &dns.Server{Addr: ":" + strconv.Itoa(c.Port), Net: "udp"}
	log.Printf("Starting at %d\n", c.Port)
	var err error
	go func() {
		err = server.ListenAndServe()
	}()
	defer server.Shutdown()
	if err != nil {
		log.Fatalf("Failed to start server: %s\n ", err.Error())
	}

	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		log.Fatal(err)
	}
	defer watcher.Close()

	done := make(chan bool)
	go func() {
		for {
			select {
			case event := <-watcher.Events:
				//if c.Debug {
				//	log.Println("Event %s for file %s", event, event.Name)
				//}
				if event.Name == "conf/conf.yaml" && event.Op&fsnotify.Write == fsnotify.Write {
					c.loadConf()
					if (c.Debug) {
						fmt.Printf("%#v\n", c)
					}
					log.Println("Reloaded")
				}
			case err := <-watcher.Errors:
				log.Println("error:", err)
			}
		}
	}()

	err = watcher.Add("conf/")
	if err != nil {
		log.Fatal(err)
	}
	<-done
}
