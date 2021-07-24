// Licensed to the Apache Software Foundation (ASF) under one or more
// contributor license agreements.  See the NOTICE file distributed with
// this work for additional information regarding copyright ownership.
// The ASF licenses this file to You under the Apache License, Version 2.0
// (the "License"); you may not use this file except in compliance with
// the License.  You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
package translation

import (
	"fmt"
	"strings"

	"go.uber.org/zap"
	"k8s.io/apimachinery/pkg/util/intstr"
	knativev1alpha1 "knative.dev/networking/pkg/apis/networking/v1alpha1"

	"github.com/apache/apisix-ingress-controller/pkg/id"
	"github.com/apache/apisix-ingress-controller/pkg/log"
	apisixv1 "github.com/apache/apisix-ingress-controller/pkg/types/apisix/v1"
)

func (t *translator) translateKnativeIngressV1alpha1(ing *knativev1alpha1.Ingress) (*TranslateContext, error) {
	ctx := &TranslateContext{
		upstreamMap: make(map[string]struct{}),
	}
	plugins := t.translateAnnotations(ing.Annotations)

	for i, rule := range ing.Spec.Rules {
		hosts := rule.Hosts
		if rule.HTTP == nil {
			continue
		}
		for j, httpPath := range rule.HTTP.Paths {
			// Default the path to "/" if none is passed.
			path := httpPath.Path
			if path == "" {
				path = "/"
			}
			var (
				ups *apisixv1.Upstream
				err error
			)
			knativeBackend := knativeSelectSplit(httpPath.Splits)
			servicePort := knativeBackend.ServicePort
			serviceName := fmt.Sprintf("%s.%s.%s", knativeBackend.ServiceNamespace, knativeBackend.ServiceName,
				servicePort)

			if serviceName != "" {
				ups, err = t.translateUpstreamFromKnativeIngressV1alpha1(ing.Namespace, serviceName, servicePort)
				if err != nil {
					log.Errorw("failed to translate knative ingress backend to upstream",
						zap.Error(err),
						zap.Any("knative ingress", ing),
					)
					return nil, err
				}
				ctx.addUpstream(ups)
			}
			uris := []string{httpPath.Path}
			// httpPath.Path represents a literal prefix to which this rule should apply.
			// As per the specification of Ingress path matching rule:
			// if the last element of the path is a substring of the
			// last element in request path, it is not a match, e.g. /foo/bar
			// matches /foo/bar/baz, but does not match /foo/barbaz.
			// While in APISIX, /foo/bar matches both /foo/bar/baz and
			// /foo/barbaz.
			// In order to be conformant with Ingress specification, here
			// we create two paths here, the first is the path itself
			// (exact match), the other is path + "/*" (prefix match).
			prefix := httpPath.Path
			if strings.HasSuffix(prefix, "/") {
				prefix += "*"
			} else {
				prefix += "/*"
			}
			uris = append(uris, prefix)

			route := apisixv1.NewDefaultRoute()
			route.Name = composeKnativeIngressRouteName(ing.Namespace, ing.Name, i, j)
			route.ID = id.GenID(route.Name)
			route.Hosts = hosts
			route.Uris = uris
			if len(plugins) > 0 {
				route.Plugins = *(plugins.DeepCopy())
			}
			if ups != nil {
				route.UpstreamId = ups.ID
			}
			ctx.addRoute(route)
		}
	}
	return ctx, nil
}

func (t *translator) translateUpstreamFromKnativeIngressV1alpha1(namespace string, svcName string, svcPort intstr.IntOrString) (*apisixv1.Upstream, error) {
	var portNumber int32
	if svcPort.Type == intstr.String {
		svc, err := t.ServiceLister.Services(namespace).Get(svcName)
		if err != nil {
			return nil, err
		}
		for _, port := range svc.Spec.Ports {
			if port.Name == svcPort.StrVal {
				portNumber = port.Port
				break
			}
		}
		if portNumber == 0 {
			return nil, &translateError{
				field:  "service",
				reason: "port not found",
			}
		}
	} else {
		portNumber = svcPort.IntVal
	}
	ups, err := t.TranslateUpstream(namespace, svcName, "", portNumber)
	if err != nil {
		return nil, err
	}
	ups.Name = apisixv1.ComposeUpstreamName(namespace, svcName, "", portNumber)
	ups.ID = id.GenID(ups.Name)
	return ups, nil
}

func knativeSelectSplit(splits []knativev1alpha1.IngressBackendSplit) knativev1alpha1.IngressBackendSplit {
	if len(splits) == 0 {
		return knativev1alpha1.IngressBackendSplit{}
	}
	res := splits[0]
	maxPercentage := splits[0].Percent
	if len(splits) == 1 {
		return res
	}
	for i := 1; i < len(splits); i++ {
		if splits[i].Percent > maxPercentage {
			res = splits[i]
			maxPercentage = res.Percent
		}
	}
	return res
}

func composeKnativeIngressRouteName(knativeIngressNamespace, knativeIngressName string, i, j int) string {
	return fmt.Sprintf("knative_ingress_%s_%s_%d%d", knativeIngressNamespace, knativeIngressName, i, j)
}
