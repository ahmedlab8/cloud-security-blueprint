package gatekeeper_test

import rego.v1

import data.k8sblockprivilegedcontainers
import data.k8sblockpublicloadbalancer
import data.k8sblockrootcontainers
import data.k8sdisallowlatesttag
import data.k8srequireresourcelimits

good_container := {
	"name": "app",
	"image": "ghcr.io/ahmedlab8/secure-app:1.0.0",
	"securityContext": {"runAsNonRoot": true, "runAsUser": 65532, "allowPrivilegeEscalation": false, "privileged": false},
	"resources": {"limits": {"cpu": "500m", "memory": "256Mi"}, "requests": {"cpu": "100m", "memory": "128Mi"}},
}

pod(c) := {"kind": "Pod", "metadata": {"name": "p"}, "spec": {"containers": [c]}}

deployment(c) := {"kind": "Deployment", "metadata": {"name": "d"}, "spec": {"template": {"spec": {"containers": [c]}}}}

review(obj) := {"review": {"object": obj}, "parameters": {}}

# ---------- root ----------
test_root_good_pod_allowed if {
	count(k8sblockrootcontainers.violation) == 0 with input as review(pod(good_container))
}

test_root_missing_run_as_non_root_denied if {
	c := object.remove(good_container, ["securityContext"])
	count(k8sblockrootcontainers.violation) > 0 with input as review(deployment(c))
}

test_root_uid_zero_denied if {
	c := json.patch(good_container, [{"op": "replace", "path": "/securityContext/runAsUser", "value": 0}])
	count(k8sblockrootcontainers.violation) > 0 with input as review(pod(c))
}

test_root_pod_level_non_root_allowed if {
	c := object.remove(good_container, ["securityContext"])
	p := {"kind": "Pod", "metadata": {"name": "p"}, "spec": {"securityContext": {"runAsNonRoot": true}, "containers": [c]}}
	count(k8sblockrootcontainers.violation) == 0 with input as review(p)
}

# ---------- privileged ----------
test_privileged_good_allowed if {
	count(k8sblockprivilegedcontainers.violation) == 0 with input as review(deployment(good_container))
}

test_privileged_denied if {
	c := json.patch(good_container, [{"op": "replace", "path": "/securityContext/privileged", "value": true}])
	count(k8sblockprivilegedcontainers.violation) > 0 with input as review(pod(c))
}

test_privilege_escalation_denied if {
	c := json.patch(good_container, [{"op": "remove", "path": "/securityContext/allowPrivilegeEscalation"}])
	count(k8sblockprivilegedcontainers.violation) > 0 with input as review(pod(c))
}

test_host_pid_denied if {
	p := {"kind": "Pod", "metadata": {"name": "p"}, "spec": {"hostPID": true, "containers": [good_container]}}
	count(k8sblockprivilegedcontainers.violation) > 0 with input as review(p)
}

# ---------- latest tag ----------
test_tag_pinned_allowed if {
	count(k8sdisallowlatesttag.violation) == 0 with input as review(pod(good_container))
}

test_digest_allowed if {
	c := json.patch(good_container, [{"op": "replace", "path": "/image", "value": "nginx@sha256:0000000000000000000000000000000000000000000000000000000000000000"}])
	count(k8sdisallowlatesttag.violation) == 0 with input as review(pod(c))
}

test_latest_denied if {
	c := json.patch(good_container, [{"op": "replace", "path": "/image", "value": "nginx:latest"}])
	count(k8sdisallowlatesttag.violation) > 0 with input as review(pod(c))
}

test_no_tag_denied if {
	c := json.patch(good_container, [{"op": "replace", "path": "/image", "value": "registry.local:5000/team/nginx"}])
	count(k8sdisallowlatesttag.violation) > 0 with input as review(pod(c))
}

test_registry_port_with_tag_allowed if {
	c := json.patch(good_container, [{"op": "replace", "path": "/image", "value": "registry.local:5000/team/nginx:1.27.1"}])
	count(k8sdisallowlatesttag.violation) == 0 with input as review(pod(c))
}

# ---------- resource limits ----------
test_limits_allowed if {
	count(k8srequireresourcelimits.violation) == 0 with input as review(deployment(good_container))
}

test_missing_memory_limit_denied if {
	c := json.patch(good_container, [{"op": "remove", "path": "/resources/limits/memory"}])
	count(k8srequireresourcelimits.violation) == 1 with input as review(pod(c))
}

test_missing_resources_denied if {
	c := object.remove(good_container, ["resources"])
	count(k8srequireresourcelimits.violation) == 4 with input as review(pod(c))
}

# ---------- public load balancer ----------
lb(annotations) := {"kind": "Service", "metadata": {"name": "web", "annotations": annotations}, "spec": {"type": "LoadBalancer"}}

test_public_lb_denied if {
	count(k8sblockpublicloadbalancer.violation) == 1 with input as review(lb({}))
}

test_aws_internal_lb_allowed if {
	a := {"service.beta.kubernetes.io/aws-load-balancer-scheme": "internal"}
	count(k8sblockpublicloadbalancer.violation) == 0 with input as review(lb(a))
}

test_azure_internal_lb_allowed if {
	a := {"service.beta.kubernetes.io/azure-load-balancer-internal": "true"}
	count(k8sblockpublicloadbalancer.violation) == 0 with input as review(lb(a))
}

test_cluster_ip_allowed if {
	svc := {"kind": "Service", "metadata": {"name": "web"}, "spec": {"type": "ClusterIP"}}
	count(k8sblockpublicloadbalancer.violation) == 0 with input as review(svc)
}
