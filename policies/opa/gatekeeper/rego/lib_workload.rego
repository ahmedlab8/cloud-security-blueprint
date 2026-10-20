# Shared helpers: extract pod specs and containers from Pods and every workload kind,
# so policies give fast feedback on Deployments instead of only failing at Pod creation.
package lib.workload

import rego.v1

pod_spec(obj) := obj.spec if obj.kind == "Pod"

pod_spec(obj) := obj.spec.template.spec if {
	obj.kind in {"Deployment", "StatefulSet", "DaemonSet", "ReplicaSet", "Job", "ReplicationController"}
}

pod_spec(obj) := obj.spec.jobTemplate.spec.template.spec if obj.kind == "CronJob"

containers(obj) := array.concat(
	array.concat(object.get(pod_spec(obj), "containers", []), object.get(pod_spec(obj), "initContainers", [])),
	object.get(pod_spec(obj), "ephemeralContainers", []),
)
