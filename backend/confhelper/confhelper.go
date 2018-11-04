package confhelper

import (
	"encoding/json"
	"io/ioutil"
	"os"
	"path/filepath"
)

type config struct {
	DbConnectionString string `json:"db_connection_string"`
	JwtSecret          string `json:"jwt_secret"`
}

// ParseConfig parses the JSON configuration
func ParseConfig(relativeConfigPath string) (string, string, error) {
	ex, err := os.Executable()
	if err != nil {
		return "", "", err
	}
	exPath := filepath.Dir(ex)
	configPath := filepath.Join(exPath, relativeConfigPath)

	dat, err := ioutil.ReadFile(configPath)
	if err != nil {
		return "", "", err
	}

	conf := config{}
	if err := json.Unmarshal(dat, &conf); err != nil {
		return "", "", err
	}

	return conf.DbConnectionString, conf.JwtSecret, nil
}
