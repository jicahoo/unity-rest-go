package main

import (
	"fmt"
	"github.com/bitly/go-simplejson"
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


}