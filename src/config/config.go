package config

import (
	"encoding/json"
	"io/ioutil"
)

// Config is a Server config.
var Config struct {
	Database struct {
		Host     string
		User     string
		Dbname   string
		Password string
	}
	Clients struct {
		MinClientVersion  uint64
		NextClientVersion uint64
		MinEngineVersion  string
		NextEngineVersion string
		VerifyPgns        bool
	}
	URLs struct {
		OnNewNetwork          []string
		NetworkLocation       string
		BackupNetworkLocation string
	}
	Matches struct {
		Games      int
		Parameters []interface{}
		Threshold  float64
	}
	WebServer struct {
		Address string
	}
}

func init() {
	content, err := ioutil.ReadFile("serverconfig.json")
	if err != nil {
		panic(err)
	}
	err = json.Unmarshal(content, &Config)
	if err != nil {
		panic(err)
	}
}
