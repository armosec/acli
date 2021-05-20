package acli

import (
	"context"
	"fmt"
	"os"

	"github.com/armosec/armopa/ast"
	"github.com/armosec/armopa/rego"
	icacli "github.com/armosec/capacketsgo/cacli"
	"github.com/armosec/capacketsgo/opapolicy"
)

var (
	BackendURL    = "https://dashbe.euprod1.cyberarmorsoft.com"
	FrameworkName = "MITRE"
)

// var Rules = []string{"alert-rw-hostpath", "rule-pod-external-facing", "rule-privilege-escalation"}
var Rules = []string{"rule-privilege-escalation"}

func RegoHandler(workloads map[string]interface{}) (map[string][]opapolicy.RuleResponse, error) {
	loadDataFromEnv()

	regoList, err := GetRego()
	if err != nil {
		return nil, err
	}
	ruleResponses := make(map[string][]opapolicy.RuleResponse)
	for fileName, workload := range workloads {
		response, err := RunRego(regoList, workload)
		if err != nil {
			return ruleResponses, err
		}
		ruleResponses[fileName] = response
	}
	return ruleResponses, nil
}

func RunRego(rules []opapolicy.PolicyRule, inputObj interface{}) ([]opapolicy.RuleResponse, error) {
	modules := make(map[string]string)
	for i := range rules {
		modules[rules[i].Name] = rules[i].Rule
	}
	compiled, err := ast.CompileModules(modules)
	if err != nil {
		return nil, err
	}
	rego := rego.New(
		rego.Query("data.armo_builtins"),
		rego.Compiler(compiled),
		rego.Input(inputObj),
	)

	// Run evaluation
	resultSet, err := rego.Eval(context.Background())
	if err != nil {
		return nil, fmt.Errorf("In 'regoEval', failed to evaluate rule, reason: %s", err.Error())
	}
	results, err := opapolicy.ParseRegoResult(&resultSet)
	if err != nil {
		return results, err
	}
	return results, nil
}

func GetRego() ([]opapolicy.PolicyRule, error) {
	rules := []opapolicy.PolicyRule{}

	cacli := icacli.NewCacli(BackendURL, true)
	framework, err := cacli.OPAFRAMEWORKGet(FrameworkName)
	if err != nil {
		return rules, err
	}
	for f := range framework {
		for c := range framework[f].Controls {
			for r := range framework[f].Controls[c].Rules {
				if !ignoreRule(framework[f].Controls[c].Rules[r].Name) {
					rules = append(rules, framework[f].Controls[c].Rules[r])
				}
			}
		}
	}
	return rules, err
}

func ignoreRule(ruleName string) bool {
	for i := range Rules {
		if Rules[i] == ruleName {
			return false
		}
	}
	return true
}

func loadDataFromEnv() {
	if env := os.Getenv("CABackendURL"); env != "" {
		BackendURL = env
	}
	if frameworksName := os.Getenv("CAFrameworkName"); frameworksName != "" {
		FrameworkName = frameworksName
	}
}
