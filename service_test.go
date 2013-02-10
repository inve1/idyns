package main

import "testing"
import "net/http"
import "net/url"
import "strings"
import "net/http/httptest"
import "github.com/jameskeane/bcrypt"
import "github.com/vmihailenco/redis"

var server *httptest.Server

func InitTests() {
    server = httptest.NewServer(createRouter())
    connectToRedis = func() *redis.Client {
        // CONFIGURE THIS!
        password := ""
        client := redis.NewTCPClient("localhost:6379", password, 1)
        return client
    }
    client := connectToRedis()
    defer client.Close()
    client.FlushDb()
    // Bootstrap the system, with an admin
    hash, _ := bcrypt.Hash("asdf")
    client.HMSet("user:admin", "isadmin", "1", "password", hash)
}


func TestCreateUserNoAuth(t *testing.T) {
    InitTests()
    resp, err := http.PostForm(server.URL + "/u/gino/",
                            url.Values{"password": {"berlino"}, "isadmin": {"1"}})

    if err != nil {
        t.Errorf("%v", err)
    }
    if resp.StatusCode != 403 {
        t.Errorf("Server responded with %v, expected 403", resp.StatusCode)
        t.FailNow()
    }
    client := connectToRedis()
    defer client.Close()
    if client.Exists("user:gino").Val() {
        t.Errorf("User was created without permission")
    }
}

func TestCreateUser(t *testing.T){
    InitTests()
    req, _ := http.NewRequest("POST", server.URL + "/u/gino/", strings.NewReader(url.Values{"password": {"berlino"}, "isadmin": {"1"}}.Encode()))
    req.SetBasicAuth("admin", "asdf")
    resp, err := http.DefaultClient.Do(req)

    if err != nil {
        t.Errorf("%v", err)
    }
    if resp.StatusCode != 200 {
        t.Errorf("Server responded with %v, expected 200", resp.StatusCode)
        t.FailNow()
    }
    client := connectToRedis()
    defer client.Close()
    v := client.HGetAll("user:gino").Val()
    if !(bcrypt.Match("berlino", v[3])) {
        t.Errorf("%v v1 is %v and v2 is %v %v", v[0], v[1], v[2], v[3])
        t.FailNow()
    }
}
