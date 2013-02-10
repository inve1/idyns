package main

import (
    "fmt"
    "net/http"
	"github.com/gorilla/mux"
)


func DynUpdate(w http.ResponseWriter, r *http.Request) {
	auth, _ := NewBasicFromRequest(r)
    name := r.FormValue("hostname") + "."
    myip := r.FormValue("myip")
    if checkPermRR(auth, name) {
        client := connectToRedis()
        defer client.Close()
        if !client.Exists("rr:" + name).Val() {
            client.HMSet("rr:"+name, "CLASS", "IN")
            client.HMSet("rr:"+name, "TTL", "3600")
            client.LPush("user:" + auth.Username + ":permissions", name)
        }
        client.HMSet("rr:"+name, "A", myip)
        fmt.Fprintf(w, "good")
        // TODO: need to implement real return codes
    } else {
        fmt.Fprint(w, "bad")
    }
}



func createRouterDyn() *mux.Router {
    r := mux.NewRouter()
    r.HandleFunc("/update", DynUpdate).Name("dynupdate").Methods("GET")
    return r
}
