package main

import (
	"crypto/tls"
	"fmt"
	"github.com/bitly/go-simplejson"
	"github.com/levigross/grequests"
	"golang.org/x/net/publicsuffix"
	"io/ioutil"
	"net/http"
	"net/http/cookiejar"
	"strings"
)
var json_str string = `{"rc" : 0,
  "error" : "Success",
  "type" : "stats",
  "progress" : 100,
  "job_status" : "COMPLETED",
  "result" : {
    "total_hits" : 803254,
    "starttime" : 1528434707000,
    "endtime" : 1528434767000,
    "fields" : [ ],
    "timeline" : {
      "interval" : 1000,
      "start_ts" : 1528434707000,
      "end_ts" : 1528434767000,
      "rows" : [ {
        "start_ts" : 1528434707000,
        "end_ts" : 1528434708000,
        "number" : "x12887"
      }, {
        "start_ts" : 1528434720000,
        "end_ts" : 1528434721000,
        "number" : "x13028"
      }, {
        "start_ts" : 1528434721000,
        "end_ts" : 1528434722000,
        "number" : "x12975"
      }, {
        "start_ts" : 1528434722000,
        "end_ts" : 1528434723000,
        "number" : "x12879"
      }, {
        "start_ts" : 1528434723000,
        "end_ts" : 1528434724000,
        "number" : "x13989"
      } ],
      "total" : 803254
    },
      "total" : 8
  }
}`

var rest_json string = `{
  "@base": "https://10.244.223.61/api/types/lun/instances?fields=id,health,name,description,type,sizeTotal,sizeUsed,sizeAllocated,compressionSizeSaved,compressionPercent,perTierSizeUsed,isThinEnabled,isCompressionEnabled,wwn,tieringPolicy,defaultNode,isReplicationDestination,currentNode,isSnapSchedulePaused,metadataSize,metadataSizeAllocated,snapWwn,snapsSize,snapsSizeAllocated,hostAccess,snapCount,snapSchedule.id,storageResource.id,pool.id,ioLimitPolicy.id&per_page=2000&compact=true",
  "updated": "2016-08-19T08:47:14.345Z",
  "links": [
    {
      "rel": "self",
      "href": "&page=1"
    }
  ],
  "entries": [
    {
      "content": {
        "id": "sv_1",
        "type": 2,
        "tieringPolicy": 0,
        "defaultNode": 1,
        "currentNode": 1,
        "health": {
          "value": 5,
          "descriptionIds": [
            "ALRT_VOL_OK"
          ],
          "descriptions": [
            "The LUN is operating normally. No action is required."
          ]
        },
        "name": "lun1",
        "description": "",
        "sizeTotal": 5368709120,
        "sizeAllocated": 0,
        "compressionSizeSaved": 0,
        "compressionPercent": 0,
        "perTierSizeUsed": [
          2952790016,
          0,
          0
        ],
        "isThinEnabled": true,
        "isCompressionEnabled": false,
        "wwn": "60:06:01:60:15:E0:3A:00:6C:CC:AA:57:FE:07:BC:D3",
        "isReplicationDestination": false,
        "isSnapSchedulePaused": false,
        "metadataSize": 3489660928,
        "metadataSizeAllocated": 2684354560,
        "snapWwn": "60:06:01:60:15:E0:3A:00:CF:2E:61:29:07:10:46:83",
        "snapsSize": 0,
        "snapsSizeAllocated": 0,
        "snapCount": 2,
        "storageResource": {
          "id": "sv_1"
        },
        "pool": {
          "id": "pool_1"
        }
      }
    },
    {
      "content": {
        "id": "sv_2",
        "type": 2,
        "tieringPolicy": 0,
        "defaultNode": 0,
        "currentNode": 0,
        "health": {
          "value": 5,
          "descriptionIds": [
            "ALRT_VOL_OK"
          ],
          "descriptions": [
            "The LUN is operating normally. No action is required."
          ]
        },
        "name": "gounity",
        "description": "",
        "sizeTotal": 10737418240,
        "sizeAllocated": 0,
        "compressionSizeSaved": 0,
        "compressionPercent": 0,
        "perTierSizeUsed": [
          2952790016,
          0,
          0
        ],
        "isThinEnabled": true,
        "isCompressionEnabled": false,
        "wwn": "60:06:01:60:15:E0:3A:00:FF:D0:B3:57:AB:3B:6D:F1",
        "isReplicationDestination": false,
        "isSnapSchedulePaused": false,
        "metadataSize": 10468982784,
        "metadataSizeAllocated": 2684354560,
        "snapWwn": "60:06:01:60:15:E0:3A:00:99:67:E7:16:DB:12:48:E0",
        "snapsSize": 21474836480,
        "snapsSizeAllocated": 0,
        "hostAccess": [
          {
            "accessMask": 2,
            "snapshotAccess": 1,
            "host": {
              "id": "Host_5"
            }
          },
          {
            "accessMask": 2,
            "snapshotAccess": 1,
            "host": {
              "id": "Host_6"
            }
          }
        ],
        "snapCount": 2,
        "storageResource": {
          "id": "sv_2"
        },
        "pool": {
          "id": "pool_1"
        }
      }
    }
  ]
}
`

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
	res, err := simplejson.NewJson([]byte(json_str))

	if err != nil {
		fmt.Printf("%v\n", err)
		return
	}
	rows, err := res.Get("result").Get("timeline").Get("rows").Array()
	for _, row := range rows {
		fmt.Println(row)
	}

	rest_resp, rest_error := simplejson.NewJson([]byte(rest_json))
	if rest_error != nil {
		return
	}

	entries, _ := rest_resp.Get("entries").Array()
	for _, entry := range entries {
		if each_map, ok := entry.(map[string]interface{}); ok {
			fmt.Println(each_map["content"])
			if lun, ok := each_map["content"].(map[string]interface{}); ok {
				fmt.Println(lun["id"])
				fmt.Println(lun["name"])
				fmt.Println(lun["sizeTotal"])
			}

		}
	}

	mgmtIp := "10.228.49.124"
	userName := "admin"
	password := "Password123!"
	unityUrl := fmt.Sprintf("https://%s/api/types/user/instances", mgmtIp)
	fmt.Println(unityUrl)

	//url := "https://jsonplaceholder.typicode.com/todos"
	ro := &grequests.RequestOptions{
		Auth: []string{userName, password},
		//Params: map[string]string{"one": "two"},
		Headers: map[string]string{"X-EMC-REST-CLIENT": "true"},
		InsecureSkipVerify: true,
		UseCookieJar: true,
		CookieJar: cookieJar(),
		RedirectLimit: 100,
	}
	rep, e := grequests.Get(unityUrl, ro)
	fmt.Println(e)
	fmt.Println(rep.StatusCode)

	session := grequests.NewSession(ro)

	//https://godoc.org/github.com/levigross/grequests#NewSession
	resp, err := session.Get(unityUrl, ro)

	if err != nil {
		fmt.Println(err)
	}

	headers := resp.Header
	for k,v := range headers {
		fmt.Println(k,v)
	}
	fmt.Println(resp.StatusCode)
	//fmt.Println(resp.String())

	//fmt.Println(resp)
	conn := NewConnection(mgmtIp, userName, password)
	my_req, _ := conn.newRequest("https://10.228.49.124/api/types/user/instances", "", "GET")
	re, ee  := conn.do(my_req)
	fmt.Println(getRespBody(re))
	fmt.Println(ee)
}