package acli

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
		return nil, fmt.Errorf("You must provide a file name or directory")
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
	filePath := ""
	dirPath := ""

	flag.StringVar(&filePath, "inputFile", "", "File input")
	flag.StringVar(&dirPath, "inputDir", "", "Directory containing yaml/json files")
	flag.Parse()

	files := []string{}
	if dirPath != "" {
		f, err := GetFilesFromDir(dirPath)
		if err != nil {
			return files, err
		}
		files = append(files, f...)
	}
	if filePath != "" {
		files = append(files, filePath)

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

func LoadFile(filePath string) (map[string]interface{}, error) {
	if strings.HasSuffix(filePath, ".yaml") {
		return LoadYamlFile(filePath)
	} else if strings.HasSuffix(filePath, ".json") {
		return LoadJsonFile(filePath)
	} else {
		return nil, fmt.Errorf("Unknown file format")
	}
}

func LoadYamlFile(filePath string) (map[string]interface{}, error) {
	yamlObj := map[string]interface{}{}
	yamlFile, err := ioutil.ReadFile(filePath)
	if err != nil {
		return yamlObj, err
	}
	err = yaml.Unmarshal(yamlFile, &yamlObj)
	if err != nil {
		return yamlObj, err
	}
	return yamlObj, nil
}

func LoadJsonFile(filePath string) (map[string]interface{}, error) {
	jsonObj := map[string]interface{}{}
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
