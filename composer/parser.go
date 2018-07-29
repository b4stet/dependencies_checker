package composer

import (
	"encoding/json"
	"fmt"
	"os"
)

type Json struct {
	Require Require `json:"require"`
}

type Lock struct {
	Packages []*Package `json:"packages"`
}

type Package struct {
	Name    string  `json:"name"`
	Version string  `json:"version"`
	Source  Source  `json:"source"`
	Require Require `json:"require"`
	IsRoot  bool    `json:"-"`
}

type Source struct {
	Type      string `json:"type"`
	Url       string `json:"url"`
	Reference string `json:"reference"`
}

type Require map[string]string

func GetInstalledPackages(jsonPath string, lockPath string) ([]*Package, error) {
	installedPackages, err := parseLock(lockPath)
	if err != nil {
		return nil, fmt.Errorf("Failed to parse composer.lock [%v]", err)
	}

	rootPackages, err := parseJson(jsonPath)
	if err != nil {
		return nil, fmt.Errorf("Failed to parse composer.json [%v]", err)
	}

	for _, pack := range installedPackages {
		_, pack.IsRoot = rootPackages[pack.Name]
	}

	return installedPackages, nil

}

func parseJson(jsonPath string) (Require, error) {
	var cJson Json

	file, err := os.Open(jsonPath)
	defer file.Close()
	if err != nil {
		return nil, err
	}

	decoder := json.NewDecoder(file)
	err = decoder.Decode(&cJson)
	if err != nil {
		return nil, err
	}

	return cJson.Require, nil
}

func parseLock(lockPath string) ([]*Package, error) {
	var cLock Lock

	file, err := os.Open(lockPath)
	defer file.Close()
	if err != nil {
		return nil, err
	}

	decoder := json.NewDecoder(file)
	err = decoder.Decode(&cLock)
	if err != nil {
		return nil, err
	}

	return cLock.Packages, nil
}
