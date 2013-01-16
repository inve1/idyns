/*This program is free software: you can redistribute it and/or modify
  it under the terms of the GNU General Public License as published by
  the Free Software Foundation, either version 3 of the License, or
  (at your option) any later version.

  This program is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
  GNU General Public License for more details.

  You should have received a copy of the GNU General Public License
  along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/
// IDYNS [Idiotic DYnamic NameServer], a small nameserver that stores
// resource records on redis. Also implements the dyndns2 http protocol
// to allow use with widespread clients [i.e. ddclient]
// originally based on the reflect example for the dns library by Miek Gieben <miek@miek.nl>.

package main

import (
	"flag"
	"fmt"
	"github.com/miekg/dns"
	"log"
	"os"
	"os/signal"
	"runtime/pprof"
	"strings"
	"syscall"
)

const NAME = "IDYNS: "

var (
	printf   *bool
	compress *bool
	tsig     *string
	logflag  *bool
)

func logStuff(form string, a ...interface{}) {
	if *logflag {
		log.Printf(NAME+form, a...)
	}
}

func getRRStr(q dns.Question) (string, bool) {
	client := connectToRedis()
	defer client.Close()
	res := client.HMGet("rr:"+q.Name, "TTL", "CLASS", dns.TypeToString[q.Qtype]).Val()
	if res == nil {
		logStuff("No information on name %v", q.Name)
		return "", true
	}
	if res[0] == nil {
		logStuff("RR for %v is malformed: TTL missing", q.Name)
		return "", true
	}
	if res[1] == nil {
		logStuff("RR for %v is malformed: CLASS missing", q.Name)
		return "", true
	}
	if res[2] == nil {
		logStuff("No %v RR for %v", dns.TypeToString[q.Qtype], q.Name)
		return "", true
	}
	return fmt.Sprintf("%v %v %v %v %v", q.Name, res[0], res[1], dns.TypeToString[q.Qtype], res[2]), false
}

func handleRequest(w dns.ResponseWriter, r *dns.Msg) {
	var rr dns.RR
	fmt.Println(r.Question[0].Name)
	m := new(dns.Msg)
	m.SetReply(r)
	m.Compress = *compress

	rrstr, err := getRRStr(r.Question[0])
	if err {
		m.SetRcode(r, dns.RcodeNameError)
	} else {
		rr, _ = dns.NewRR(rrstr)

		m.Answer = append(m.Answer, rr)
		if *printf {
			fmt.Printf("%v\n", m.String())
		}
	}
	w.WriteMsg(m)
}

// TODO: make port and bind address configurable
func serve(net, name, secret string) {
	switch name {
	case "":
		err := dns.ListenAndServe(":53", net, nil)
		if err != nil {
			fmt.Printf("Failed to setup the "+net+" server: %s\n", err.Error())
		}
	default:
		server := &dns.Server{Addr: ":53", Net: net, TsigSecret: map[string]string{name: secret}}
		err := server.ListenAndServe()
		if err != nil {
			fmt.Printf("Failed to setup the "+net+" server: %s\n", err.Error())
		}
	}
}

func addZoneHandles() {
	client := connectToRedis()
	zones := client.Keys("zone:*").Val()
	for i := 0; i < len(zones); i++ {
		dns.HandleFunc(zones[i][5:], handleRequest)
	}
}

func main() {
	cpuprofile := flag.String("cpuprofile", "", "write cpu profile to file")
	printf = flag.Bool("print", false, "print replies")
	logflag = flag.Bool("log", false, "log stuff")
	compress = flag.Bool("compress", false, "compress replies")
	tsig = flag.String("tsig", "", "use MD5 hmac tsig: keyname:base64")
	var name, secret string
	flag.Usage = func() {
		flag.PrintDefaults()
	}
	flag.Parse()
	if *tsig != "" {
		a := strings.SplitN(*tsig, ":", 2)
		name, secret = dns.Fqdn(a[0]), a[1] // fqdn the name, which everybody forgets...
	}
	if *cpuprofile != "" {
		f, err := os.Create(*cpuprofile)
		if err != nil {
			log.Fatal(err)
		}
		pprof.StartCPUProfile(f)
		defer pprof.StopCPUProfile()
	}

	addZoneHandles()
	dns.HandleFunc("authors.bind.", dns.HandleAuthors)
	dns.HandleFunc("authors.server.", dns.HandleAuthors)
	dns.HandleFunc("version.bind.", dns.HandleVersion)
	dns.HandleFunc("version.server.", dns.HandleVersion)
	go serve("tcp", name, secret)
	go serve("udp", name, secret)
	go handleHTTP()
	sig := make(chan os.Signal)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
forever:
	for {
		select {
		case s := <-sig:
			fmt.Printf("Signal (%d) received, stopping\n", s)
			break forever
		}
	}
}
