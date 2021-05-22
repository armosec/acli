package main

import (
	"fmt"
)

func main() {
	workloads, err := HandleInput()
	if err != nil {
		fmt.Println(err.Error())
		return
	}

	response, err := RegoHandler(workloads)
	if err != nil {
		fmt.Println(err.Error())
		return
	}

	fmt.Printf("response: %v\n", response)
}
