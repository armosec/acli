module acli

go 1.13

replace github.com/armosec/capacketsgo => ./vendor/github.com/armosec/capacketsgo

require (
	github.com/armosec/armopa v0.0.2
	github.com/armosec/capacketsgo v0.0.8
	github.com/golang/glog v0.0.0-20210429001901-424d2337a529
	gopkg.in/yaml.v2 v2.4.0
)
