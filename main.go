package main

import (
	"crypto/tls"
	"fmt"
	"github.com/Jeffail/gabs"
	"github.com/bitly/go-simplejson"
	"github.com/sirupsen/logrus"
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
	conn.getNewCsrfToken()
	return conn
}

func (conn *Connection) do(req *http.Request) (*http.Response, error) {
	logrus.Info("CSRF: ", conn.csrf)
	req.Header.Set("EMC-CSRF-TOKEN", conn.csrf)
	resp, err := conn.client.Do(req)
	//log.WithField("request", req).Debug("send request.")
	if err != nil {
		//log.WithError(err).Error("http request error.")
		logrus.Error(err)
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

func (conn *Connection) getNewCsrfToken() {
	unityUrl := fmt.Sprintf("https://%s/api/types/user/instances?fields=name", conn.ip)
	resp, err := conn.request(unityUrl, "", "GET")
	if err != nil {
		logrus.Error("Failed to get new csrf token")
	} else {
		conn.updateCsrf(resp)
	}
}

func (conn *Connection) retryWithCsrfToken(req *http.Request) (*http.Response, error) {
	var (
		resp *http.Response
		err  error
	)

	//log.Info("token invalid, try to get a new token.")
	conn.getNewCsrfToken()
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
		logrus.WithError(err).Error("failed to read response body.")
	}
	respBody := string(bytes)
	logrus.WithField("body", respBody).Debug(resp)
	return respBody
}

func (conn *Connection) get(url string) (int, string) {
	my_req, _ := conn.newRequest(url, "", "GET")
	re, _ := conn.do(my_req)
	respStr := getRespBody(re)
	return re.StatusCode, respStr
}

func (conn *Connection) post(url string, body string) (int, string) {
	my_req, _ := conn.newRequest(url, body, "POST")
	re, _ := conn.do(my_req)
	respStr := getRespBody(re)
	return re.StatusCode, respStr
}

func (conn *Connection) delete(url string) (int, string) {
	my_req, _ := conn.newRequest(url, "", "DELETE")
	re, _ := conn.do(my_req)
	respStr := getRespBody(re)
	return re.StatusCode, respStr
}

func init() {
	logrus.SetLevel(logrus.DebugLevel)
}

func main() {
	fmt.Println("Fire!")

	mgmtIp := "10.228.49.124"
	userName := "admin"
	password := "Password123!"
	conn := NewConnection(mgmtIp, userName, password)

	unityUrl := fmt.Sprintf("https://%s/api/types/user/instances?fields=name", mgmtIp)
	status, respStr := conn.get(unityUrl)
	logrus.Info("Got response status: ", status)
	logrus.Debug("Got response body: ", respStr)

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

	jsonParsed, err := gabs.ParseJSON([]byte(respStr))
	if err != nil {
		logrus.Error("Json parsed error", err)
	}
	children, _ := jsonParsed.S("entries").Children()
	for _, child := range children {
		content := child.Path("content")
		logrus.Info(content.Path("name").String())
	}

	create_user_body := `{"name":"lake", "role":"operator", "password":"Password123!"}`
	unityUrl = fmt.Sprintf("https://%s/api/types/user/instances", mgmtIp)
	status, respStr = conn.post(unityUrl, create_user_body)
	logrus.Info(respStr)
	jsonParsed, err = gabs.ParseJSON([]byte(respStr))
	userId := jsonParsed.Path("content.id").Data().(string)
	logrus.Info("user id: ", userId)
	unityUrl = fmt.Sprintf("https://%s/api/instances/user/%s", mgmtIp, userId)
	logrus.Info("Delete user at url: ", unityUrl)
	status, respStr = conn.delete(unityUrl)
	logrus.Info("Status for delete: ", status)

}
