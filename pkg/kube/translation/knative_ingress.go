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
	"knative.dev/networking/pkg/apis/networking"
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
	// TODO: Ensures that apisix-ingress-controller does not pick knative ingress up when ingress.class annotation is incorrect.
	// waiting for APISIX Route to support ingress.class
	// see https://github.com/apache/apisix-ingress-controller/issues/451
	if ingClass, ok := ing.Annotations[networking.IngressClassAnnotationKey]; !ok || !strings.Contains(ingClass, "apisix") {
		log.Infow("ingress.class not configured to apisix, translation aborted",
			zap.Any("knative ingress", ing))
		//return nil, fmt.Errorf("ingress.class is configured to %s, not apisix, translation aborted", ingClass)
	}

	plugins := t.translateAnnotations(ing.Annotations)

	// TODO: TestIngressConformance/tls cannot PASS, waiting for APISIX Route to support SNI based TLS
	// see https://github.com/apache/apisix-ingress-controller/issues/547
	// ApisixTls Reference: http://apisix.apache.org/docs/ingress-controller/references/apisix_tls/
	/*
		var ssls []*apisixv1.Ssl
		for _, ingressTLS := range ing.Spec.TLS {
			ssl, err := t.translateTLSFromKnativeIngressV1alpha1(ingressTLS)
			if err != nil {
				log.Errorw("failed to translate ingressTLS to apisixSsl",
					zap.Error(err),
					zap.Any("apisixSsl", ssl),
				)
				return nil, err
			}
			ssls = append(ssls, ssl)
			log.Debugw("got SSL object from ApisixTls",
				zap.Any("ssl", ssl),
			)
		}
		ctx.Ssls = ssls
	*/

	for i, rule := range ing.Spec.Rules {
		hosts := rule.Hosts
		if rule.HTTP == nil {
			continue
		}
		var ruleExtVisibility bool
		if rule.Visibility == knativev1alpha1.IngressVisibilityExternalIP {
			ruleExtVisibility = true
		}
		// from https://github.com/knative-sandbox/net-kourier/blob/dd1b827bb5b21c874222c18fc7fc1f3c54e40ee9/pkg/generator/ingress_translator.go#L95
		//ruleName := fmt.Sprintf("(%s/%s).Rules[%d]", ing.Namespace, ing.Name, i)
		//fmt.Printf("In func translateKnativeIngressV1alpha1(): ruleName = %s", ruleName)
		//routes := make([]*route.Route, 0, len(rule.HTTP.Paths))
		for j, httpPath := range rule.HTTP.Paths {
			// TODO: no header matcher since neither APISIX Route nor APISIX Plugin (such as traffic-split) supports header matching
			// Note the N:1 mapping from rule.HTTP.Paths to httpPath and from httpPath.Splits to split
			// Default the path to "/" if none is passed.
			path := httpPath.Path
			if path == "" {
				path = "/"
			}
			headers := make(map[string]string)
			for key, value := range httpPath.AppendHeaders {
				headers[key] = value
			}
			var (
				upstreams []*apisixv1.Upstream
				percents  []int // Caution: elements in upstreams and percents are corresponding by index
			)
			for _, split := range httpPath.Splits {
				//split := knativeSelectSplit(httpPath.Splits)
				// The FQN of the service is sufficient here, as clusters towards the
				// same service are supposed to be deduplicated anyway.
				//splitName := fmt.Sprintf("%s/%s", split.ServiceNamespace, split.ServiceName)
				ingressBackend := split.IngressBackend

				if ingressBackend.ServiceName != "" {
					upstream, err := t.translateUpstreamFromKnativeIngressV1alpha1(ingressBackend.ServiceNamespace, ingressBackend.ServiceName, ingressBackend.ServicePort)
					if err != nil {
						log.Errorw("failed to translate knative ingress backend to upstream",
							zap.Error(err),
							zap.Any("knative ingress", ing),
							zap.Any("split", split),
						)
						return nil, err
					}
					upstreams = append(upstreams, upstream)
					percents = append(percents, split.Percent)
					ctx.addUpstream(upstream)
				}
				// TODO: Current APISIX Route model and Plugins do not support AppendHeaders after traffic split
				// Knative requires two phase of AppendHeaders, first for httpPath, second for each split.
				// httpPath -> AppendHeaders -> Split1 -> AppendHeaders
				//                           \
				//                            > Split2 -> AppendHeaders
				// Now appends headers from all splits.
				for key, value := range split.AppendHeaders {
					headers[key] = value
				}
			}
			route := apisixv1.NewDefaultRoute()
			// TODO: Figure out a way to name the routes (See Kong ingress controller #834)
			route.Name = composeKnativeIngressRouteName(ing.Namespace, ing.Name, i, j)
			route.ID = id.GenID(route.Name)
			route.Hosts = hosts
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
			route.Uris = uris
			route.EnableWebsocket = true
			if !ruleExtVisibility {
				// host and hosts, remote_addr and remote_addrs cannot exist at the same time, only one of them can be selected.
				// If enabled at the same time, the API will respond with an error.
				//route.RemoteAddrs = []string{"10.96.0.0/16"}
			}

			// add APISIX plugin "proxy-rewrite" to support KIngress' `appendHeaders` property
			var proxyRewritePlugin apisixv1.RewriteConfig
			if len(headers) > 0 || httpPath.RewriteHost != "" {
				proxyRewritePlugin.RewriteHeaders = headers
				proxyRewritePlugin.RewriteHost = httpPath.RewriteHost
				plugins["proxy-rewrite"] = proxyRewritePlugin
			}

			if len(upstreams) > 0 {
				route.UpstreamId = upstreams[0].ID
			}
			var trafficSplitPlugin apisixv1.TrafficSplitConfig
			if len(upstreams) > 1 && len(upstreams) == len(percents) {
				var trafficSplitConfigRule apisixv1.TrafficSplitConfigRule
				var weightedUpstream apisixv1.TrafficSplitConfigRuleWeightedUpstream
				weightedUpstream.Weight = percents[0]
				trafficSplitConfigRule.WeightedUpstreams = append(trafficSplitConfigRule.WeightedUpstreams, *weightedUpstream.DeepCopy())
				for i := 1; i < len(upstreams); i++ {
					weightedUpstream.UpstreamID = upstreams[i].ID
					weightedUpstream.Weight = percents[i] // won't panic since upstreams and percents are of equal length
					trafficSplitConfigRule.WeightedUpstreams = append(trafficSplitConfigRule.WeightedUpstreams, *weightedUpstream.DeepCopy())
				}
				trafficSplitPlugin.Rules = append(trafficSplitPlugin.Rules, trafficSplitConfigRule)
				plugins["traffic-split"] = trafficSplitPlugin
			}

			if len(plugins) > 0 {
				route.Plugins = *(plugins.DeepCopy())
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
			log.Errorf("In translateUpstreamFromKnativeIngressV1alpha1(): service not found",
				zap.String("namespace", namespace),
				zap.String("svcName", svcName),
				zap.Any("svcPort", svcPort))
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

func (t *translator) translateTLSFromKnativeIngressV1alpha1(tls knativev1alpha1.IngressTLS) (*apisixv1.Ssl, error) {
	s, err := t.SecretLister.Secrets(tls.SecretNamespace).Get(tls.SecretName)
	if err != nil {
		return nil, err
	}
	cert, ok := s.Data["cert"]
	if !ok {
		return nil, ErrEmptyCert
	}
	key, ok := s.Data["key"]
	if !ok {
		return nil, ErrEmptyPrivKey
	}
	var snis []string
	for _, host := range tls.Hosts {
		snis = append(snis, host)
	}
	ssl := &apisixv1.Ssl{
		ID:     id.GenID(tls.SecretNamespace + "_" + tls.SecretName),
		Snis:   snis,
		Cert:   string(cert),
		Key:    string(key),
		Status: 1,
		Labels: map[string]string{
			"managed-by": "apisix-ingress-controller",
		},
	}
	return ssl, nil
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
	// TODO: convert fmt to buf like to align compose funcs in other files
	return fmt.Sprintf("knative_ingress_%s_%s_%d%d", knativeIngressNamespace, knativeIngressName, i, j)
	//p := make([]byte, 0, len(host)+len(path)+len("knative_ingress")+2)
	//buf := bytes.NewBuffer(p)
	//
	//buf.WriteString("knative_ingress")
	//buf.WriteByte('_')
	//buf.WriteString(host)
	//buf.WriteByte('_')
	//buf.WriteString(path)
	//
	//return buf.String()
}
