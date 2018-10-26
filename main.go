package main

import (
	"crypto/tls"
	"fmt"
	"github.com/bitly/go-simplejson"
	"golang.org/x/net/publicsuffix"
	"io/ioutil"
	"net/http"
	"net/http/cookiejar"
	"strings"
)

type Connection struct {
	ip       string
	username string
	password string
	client   *http.Client
	fields   map[string]string
	useMock  bool
	csrf     string
}

func NewConnection(ip, username, password string) *Connection {
	c := &Connection{ip, username, password, nil, make(map[string]string), false, ""}
	return c.init()
}

func redirectPolicyFunc(req *http.Request, via []*http.Request) error {
	// if redirected , use the header of the first request
	//log.WithField("request", req).Debug("request redirected.")
	req.Header = via[0].Header
	return nil
}

func transport() *http.Transport {
	return &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}
}

func cookieJar() *cookiejar.Jar {
	options := cookiejar.Options{PublicSuffixList: publicsuffix.List}
	jar, _ := cookiejar.New(&options)
	//if err != nil {
	//	log.Error(err)
	//}
	return jar
}

func (conn *Connection) init() *Connection {
	conn.client = &http.Client{
		Transport: transport(), Jar: cookieJar(), CheckRedirect: redirectPolicyFunc}
	conn.fields["type"] = ""
	return conn
}

func (conn *Connection) do(req *http.Request) (*http.Response, error) {
	req.Header.Set("EMC-CSRF-TOKEN", conn.csrf)
	resp, err := conn.client.Do(req)
	//log.WithField("request", req).Debug("send request.")
	if err != nil {
		//log.WithError(err).Error("http request error.")
		return nil, err
	}
	//log.WithField("response", resp).Debug("got response.")
	return resp, err
}

var HEADERS map[string]string = map[string]string{
	"Accept":            "application/json",
	"Content-Type":      "application/json",
	"Accept_Language":   "en_US",
	"X-EMC-REST-CLIENT": "true",
	"User-Agent":        "gounity",
}

func (conn *Connection) newRequest(url, body, method string) (*http.Request, error) {
	req, err := http.NewRequest(method, url, strings.NewReader(body))
	if err != nil {
		//log.WithError(err).Error("create request error.")
		return nil, err
	}
	req.SetBasicAuth(conn.username, conn.password)
	for k, v := range HEADERS {
		req.Header.Add(k, v)
	}
	return req, err
}

func (conn *Connection) request(url, body, method string) (*http.Response, error) {
	req, err := conn.newRequest(url, body, method)
	if err != nil {
		return nil, err
	}

	var resp *http.Response
	resp, err = conn.do(req)
	if resp.StatusCode == 401 && method != "GET" {
		req, err := conn.newRequest(url, body, method)
		if err != nil {
			return nil, err
		}
		resp, err = conn.retryWithCsrfToken(req)
	}
	return resp, err
}

func (conn *Connection) updateCsrf(resp *http.Response) {
	newToken := resp.Header.Get("Emc-Csrf-Token")
	if conn.csrf != newToken {
		conn.csrf = newToken
		//log.WithField("csrf-token", conn.csrf).Info("update csrf token.")
	}
}

func (conn *Connection) retryWithCsrfToken(req *http.Request) (*http.Response, error) {
	var (
		resp *http.Response
		err  error
	)

	//log.Info("token invalid, try to get a new token.")
	pathUser := "/api/types/user/instances"
	resp, err = conn.request(pathUser, "", "GET")
	if err != nil {
		//log.WithError(err).Error("failed to get csrf-token.")
	} else {
		conn.updateCsrf(resp)
		resp, err = conn.do(req)
	}
	return resp, err
}

func getRespBody(resp *http.Response) string {
	defer resp.Body.Close()

	bytes, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		//log.WithError(err).Error("failed to read response body.")
		fmt.Errorf("Erro")
	}
	respBody := string(bytes)
	//log.WithField("body", respBody).Debug(resp)
	return respBody
}

func main() {
	fmt.Println("Fire!")

	mgmtIp := "10.228.49.124"
	userName := "admin"
	password := "Password123!"
	unityUrl := fmt.Sprintf("https://%s/api/types/user/instances?fields=name", mgmtIp)
	conn := NewConnection(mgmtIp, userName, password)
	my_req, _ := conn.newRequest(unityUrl, "", "GET")
	re, _ := conn.do(my_req)
	respStr := getRespBody(re)
	res, _ := simplejson.NewJson([]byte(respStr))

	entries, _ := res.Get("entries").Array()
	for _, entry := range entries {
		if each_map, ok := entry.(map[string]interface{}); ok {
			fmt.Println(each_map["content"])
			if lun, ok := each_map["content"].(map[string]interface{}); ok {
				fmt.Println(lun["id"])
				fmt.Println(lun["name"])
			}

		}
	}
}
