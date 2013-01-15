package main

import (
	"fmt"
	"github.com/vmihailenco/redis"
	"log"
	"net/http"
	"regexp"
    "github.com/gorilla/mux"
    "github.com/jameskeane/bcrypt"
)

func connectToRedis() *redis.Client {
    password := "" // no password set
    return redis.NewTCPClient("localhost:6379", password, -1) 
}

func serveHTTP() {

	http.HandleFunc("/nic/update", func(w http.ResponseWriter, r *http.Request) {
		hostname := r.FormValue("hostname")
		myip := r.FormValue("myip")
		reg, _ := regexp.Compile(`^(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])$`)
		if reg.MatchString(myip) {
			// TODO: authentication :P
            client := connectToRedis()
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


func getSecret(user, realm string) string {
    client := connectToRedis()
    defer client.Close()
    return client.HMGet("user:" + user, "password").Val()[0].(string)
}

func checkAdm(auth *Basic) bool {
    return true
    client := connectToRedis()
    defer client.Close()
    if checkUserPass(auth.Username, auth.Password, client) {
        if client.HGet("user:" + auth.Username, "isadmin").Val() == "1" {
            return true
        }
    }
    return false
}

// Returns false if the password does not match or if the user is not there
func checkUserPass(user string, pass string, client *redis.Client) bool {
    if client.Exists("user:" + user).Val() {
        if bcrypt.Match(pass, client.HMGet("user:" + user, "password").Val()[0].(string)) {
            return true
        }
    }
    return false
}

func checkPerm(auth *Basic, name string) bool {
    client := connectToRedis()
    defer client.Close()
    if checkUserPass(auth.Username, auth.Password, client) {
        if client.HGet("user:" + auth.Username, "isadmin").Val() == "1" {
            return true
        }
        return client.SIsMember("user:" + auth.Username + ":permissions", name).Val()
    }
    return false
}

func NameGet(w http.ResponseWriter, r *http.Request) {}



func NameGetType(w http.ResponseWriter, r *http.Request) {}
func NamePutType(w http.ResponseWriter, r *http.Request) {}
func NamePostType(w http.ResponseWriter, r *http.Request) {
    name := mux.Vars(r)["name"]
    rrtype := mux.Vars(r)["type"]
    rrvalue := r.FormValue("value")
    auth, _ := NewBasicFromRequest(r)
    if checkPerm(auth, name)  { 
        client := connectToRedis()
        defer client.Close()
        if client.HExists("rr:" + name, rrtype).Val() {
            http.Error(w, "", 409)
        } else {
            client.HMSet("rr:" + name, rrtype, rrvalue)
            fmt.Fprintf(w, "") 
        }
    } else {
        http.Error(w, "", 403)
    }

}
func NameDeleteType(w http.ResponseWriter, r *http.Request) {
    name := mux.Vars(r)["name"]
    rrtype := mux.Vars(r)["type"]
    auth, _ := NewBasicFromRequest(r)
    if checkPerm(auth, name)  { 
        client := connectToRedis()
        defer client.Close()
        if !client.HExists("rr:" + name, rrtype).Val() {
            http.Error(w, "", 404)
        } else {
            client.HDel("rr:" + name, rrtype)
            fmt.Fprintf(w, "") 
        }
    } else {
        http.Error(w, "", 403)
    }

}

func UserPut(w http.ResponseWriter, r *http.Request) {}
func UserPost(w http.ResponseWriter, r *http.Request) {
    name := mux.Vars(r)["username"]
    isadmin := r.FormValue("isadmin")
    password := r.FormValue("password")
    auth, _ := NewBasicFromRequest(r)
    if checkAdm(auth)  { 
        client := connectToRedis()
        defer client.Close()
        if client.Exists("user:" + name).Val() {
            http.Error(w, "", 409)
        } else {
            hash, _ := bcrypt.Hash(password)
            client.HMSet("user:" + name, "isadmin", isadmin, "password", hash)
            fmt.Fprintf(w, "") 
        }
    } else {
        http.Error(w, "", 403)
    }

}
func UserDelete(w http.ResponseWriter, r *http.Request) {
    name := mux.Vars(r)["username"]
    auth, _ := NewBasicFromRequest(r)
    if checkAdm(auth)  { 
        client := connectToRedis()
        defer client.Close()
        if !client.Exists("user:" + name).Val() {
            http.Error(w, "", 404)
        } else {
            client.Del("user:" + name)
            fmt.Fprintf(w, "") 
        }
    } else {
        http.Error(w, "", 403)
    }

}

func handleHTTP() {
    r := mux.NewRouter()
    subRR := r.PathPrefix("/RR").Subrouter()
    subU := r.PathPrefix("/u").Subrouter()
    subRR.HandleFunc("/{name}/", NameGet).Name("nameget").Methods("GET")
    subRR.HandleFunc("/{name}/{type}/", NameGetType).Name("namegettype").Methods("GET")
    subRR.HandleFunc("/{name}/{type}/", NamePutType).Name("nameputtype").Methods("PUT")
    subRR.HandleFunc("/{name}/{type}/", NamePostType).Name("nameposttype").Methods("POST")
    subRR.HandleFunc("/{name}/{type}/", NameDeleteType).Name("namedeletetype").Methods("DELETE")

//    subU.HandleFunc("/{username}/", NameDeleteType).Name("nameget").Methods("GET") Don't know yet
    subU.HandleFunc("/{username}/", UserPut).Name("userput").Methods("PUT")
    subU.HandleFunc("/{username}/", UserPost).Name("userpost").Methods("POST")
    subU.HandleFunc("/{username}/", UserDelete).Name("userdelete").Methods("DELETE")
    http.Handle("/", r)
	log.Fatal(http.ListenAndServe(":8080", nil))
}
