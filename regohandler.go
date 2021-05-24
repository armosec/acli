package main

import (
	"context"
	"fmt"

	"github.com/armosec/armopa/ast"
	"github.com/armosec/armopa/rego"

	icacli "github.com/armosec/capacketsgo/cacli"
	"github.com/armosec/capacketsgo/opapolicy"
)

var (
	FrameworkName = "MITRE"
)

var Rules = []string{
	// "rule-identify-blacklisted-image-registries",
	// "rule-list-all-cluster-admins",
	"alert-rw-hostpath",
	// "exec-into-container",
	// "rule-access-dashboard",
	// "instance-metadata-api-access",
	// "internal-networking",
	"rule-privilege-escalation",
	// "rule-exposed-dashboard",
	// "rule-deny-access-to-secrets",
	// "rule-deny-cronjobs",
	"alert-any-hostpath",
	// "rule-pod-external-facing",
	// "deny-vuln-image-pods",
	// "access-container-service-account",
	// "rule-can-ssh-to-pod",
}

// var Rules = []string{"rule-privilege-escalation"}

func RegoHandler(workloads map[string]interface{}) (map[string][]opapolicy.RuleResponse, error) {

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
	modules := RegoDependencies() // resources.LoadRegoFiles("vendor/github.com/armosec/capacketsgo/opapolicy/resources/rego/dependencies/")
	if len(modules) == 0 {
		return nil, fmt.Errorf("Failed to load dependencies")
	}
	for i := range rules {
		modules[rules[i].Name] = rules[i].Rule
	}
	compiled, err := ast.CompileModules(modules)
	if err != nil {
		return nil, err
	}

	compiledRego := rego.New(
		rego.Query("data.armo_builtins"),
		rego.Compiler(compiled),
		rego.Input(inputObj),
	)

	// Run evaluation
	resultSet, err := compiledRego.Eval(context.Background())
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

	cacli := icacli.NewCacliWithoutLogin()
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

func RegoDependencies() map[string]string {
	d := make(map[string]string)
	d["cautils"] = UtilsDependency()
	return d
}

func UtilsDependency() string {
	return `
package cautils

list_contains(lista,element) {
  some i
  lista[i] == element
}


# getPodName(metadata) = name {
# 	name := metadata.generateName
#}
getPodName(metadata) = name {
	name := metadata.name
}


#returns subobject ,sub1 is partial to parent,  e.g parent = {a:a,b:b,c:c,d:d}
# sub1 = {b:b,c:c} - result is {b:b,c:c}, if sub1={b:b,e:f} returns {b:b}
object_intersection(parent,sub1) = r{
  
  r := {k:p  | p := sub1[k]
              parent[k]== p
              }
}

#returns if parent contains sub(both are objects not sets!!)
is_subobject(sub,parent) {
object_intersection(sub,parent)  == sub
}

`
}
