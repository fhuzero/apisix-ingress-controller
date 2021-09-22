module github.com/apache/apisix-ingress-controller

go 1.13

require (
	github.com/gin-gonic/gin v1.6.3
	github.com/gogo/protobuf v1.3.2
	github.com/gorilla/websocket v1.4.2
	github.com/hashicorp/go-memdb v1.0.4
	github.com/hashicorp/go-multierror v1.1.0
	github.com/imdario/mergo v0.3.11 // indirect
	github.com/onsi/gomega v1.10.3 // indirect
	github.com/prometheus/client_golang v1.11.0
	github.com/prometheus/client_model v0.2.0
	github.com/rs/dnscache v0.0.0-20210201191234-295bba877686
	github.com/spf13/cobra v1.1.1
	github.com/stretchr/testify v1.7.0
	go.uber.org/multierr v1.6.0
	go.uber.org/zap v1.19.1
	golang.org/x/net v0.0.0-20210917221730-978cfadd31cf
	google.golang.org/grpc v1.40.0
	gopkg.in/check.v1 v1.0.0-20200902074654-038fdea0a05b // indirect
	gopkg.in/yaml.v2 v2.4.0
	k8s.io/api v0.21.4
	k8s.io/apimachinery v0.21.4
	k8s.io/client-go v0.21.4
	k8s.io/code-generator v0.21.4
	knative.dev/networking v0.0.0-20210920060835-9dcf81a6d6e4
	knative.dev/pkg v0.0.0-20210921102337-b708bdee240d
)
