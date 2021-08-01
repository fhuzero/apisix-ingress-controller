#!/usr/bin/env bash
#
# Licensed to the Apache Software Foundation (ASF) under one or more
# contributor license agreements.  See the NOTICE file distributed with
# this work for additional information regarding copyright ownership.
# The ASF licenses this file to You under the Apache License, Version 2.0
# (the "License"); you may not use this file except in compliance with
# the License.  You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
# This script runs e2e tests in a local kind environment.
#

set -euo pipefail

APISIX_NAMESPACE=ingress-apisix

export KO_DOCKER_REPO=kind.local
export KIND_CLUSTER_NAME="ingress-apisix-knative"
. ./upload-test-images.sh

echo ">> Setup test resources"
# TODO: check whether .yaml files under test/config need to be revised
ko apply -f test/config

#ip=$(kubectl get nodes -lkubernetes.io/hostname!=kind-control-plane -ojsonpath='{.items[*].status.addresses[?(@.type=="InternalIP")].address}' | head -n1)
export NODE_IP=$(kubectl get nodes --namespace ${APISIX_NAMESPACE} -o jsonpath="{.items[0].status.addresses[0].address}")
echo
export "GATEWAY_OVERRIDE=apisix"
export "GATEWAY_NAMESPACE_OVERRIDE=${APISIX_NAMESPACE}"

echo ">> Running conformance tests"
# timeout is 1m to failfast since the test always timed out
go test -count=1 -short -timeout=5m -tags=e2e -test.v ./conformance/... ./e2e/... \
  --ingressendpoint=${NODE_IP} \
  --ingressClass=apisix
