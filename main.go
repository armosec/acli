package acli

import "github.com/golang/glog"

func main() {
	workloads, err := HandleInput()
	if err != nil {
		glog.Exitf(err.Error())
	}

	response, err := RegoHandler(workloads)
	if err != nil {
		glog.Exitf(err.Error())
	}

	glog.Infof("%v", response)
}
