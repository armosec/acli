package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v2"
)

func HandleInput() (map[string]interface{}, error) {
	files, err := flagParser()
	if err != nil {
		return nil, err
	}
	if len(files) == 0 {
		return nil, fmt.Errorf("No files found. Please make sure you provided a full path")
	}
	workloads := make(map[string]interface{})
	for i := range files {
		content, err := LoadFile(files[i])
		if err != nil {
			return workloads, err
		}
		workloads[files[i]] = content
	}
	return workloads, nil
}

func flagParser() ([]string, error) {
	dirPath := ""

	// flag.Set("alsologtostderr", "1")
	flag.StringVar(&dirPath, "input", "", "Full path to a directory or file")
	flag.Parse()

	if dirPath == "" {
		return nil, fmt.Errorf("Please provide full path to a file/directory")
	}

	files, err := GetFilesFromDir(dirPath)
	if err != nil {
		return files, err
	}

	return files, nil
}
func GetFilesFromDir(fileDir string) ([]string, error) {
	var files []string
	err := filepath.Walk(fileDir, func(path string, info os.FileInfo, err error) error {
		if !info.IsDir() {
			if strings.HasSuffix(info.Name(), ".yaml") || strings.HasSuffix(info.Name(), ".json") {
				files = append(files, path)
			}
		}
		return nil
	})
	return files, err
}

func LoadFile(filePath string) (interface{}, error) {
	if strings.HasSuffix(filePath, ".yaml") {
		return LoadYamlFile(filePath)
	} else if strings.HasSuffix(filePath, ".json") {
		return LoadJsonFile(filePath)
	} else {
		return nil, fmt.Errorf("Unknown file format")
	}
}

func LoadYamlFile(filePath string) (interface{}, error) {
	var yamlObj interface{}
	yamlFile, err := ioutil.ReadFile(filePath)
	if err != nil {
		return yamlObj, err
	}

	if err := yaml.Unmarshal(yamlFile, &yamlObj); err != nil {
		return yamlObj, err
	}
	return convertYamlToJson(yamlObj), nil
}

func LoadJsonFile(filePath string) (interface{}, error) {
	var jsonObj interface{}
	jsonFile, err := ioutil.ReadFile(filePath)
	if err != nil {
		return jsonObj, err
	}
	err = json.Unmarshal(jsonFile, &jsonObj)
	if err != nil {
		return jsonObj, err
	}
	return jsonObj, nil
}

func convertYamlToJson(i interface{}) interface{} {
	switch x := i.(type) {
	case map[interface{}]interface{}:
		m2 := map[string]interface{}{}
		for k, v := range x {
			m2[k.(string)] = convertYamlToJson(v)
		}
		return m2
	case []interface{}:
		for i, v := range x {
			x[i] = convertYamlToJson(v)
		}
	}
	return i
}
