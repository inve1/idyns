package main

import (
	"fmt"
	"github.com/vmihailenco/redis"
	"log"
	"net/http"
	"regexp"
)

func serveHTTP() {

	http.HandleFunc("/nic/update", func(w http.ResponseWriter, r *http.Request) {
		hostname := r.FormValue("hostname")
		myip := r.FormValue("myip")
		reg, _ := regexp.Compile(`^(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])$`)
		if reg.MatchString(myip) {
			// TODO: authentication :P

			password := "" // no password set
			client := redis.NewTCPClient("localhost:6379", password, -1)
			defer client.Close()
			client.HMSet("rr:"+hostname+".", "A", myip, "TTL", "3600", "CLASS", "IN")
			logStuff("A RR for %v updated to %v", hostname, myip)
			fmt.Fprintf(w, "good")
		} else {
			fmt.Fprintf(w, "bad")
		}
	})

	log.Fatal(http.ListenAndServe(":8080", nil))

}
