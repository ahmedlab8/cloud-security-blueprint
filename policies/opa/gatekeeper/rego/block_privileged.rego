package k8sblockprivilegedcontainers

import rego.v1

# Shared helpers are shipped to Gatekeeper via the template's `libs` field.
import data.lib.workload

violation contains {"msg": msg} if {
	some c in workload.containers(input.review.object)
	c.securityContext.privileged == true
	msg := sprintf("privileged container <%v> is not allowed", [c.name])
}

violation contains {"msg": msg} if {
	some c in workload.containers(input.review.object)
	not c.securityContext.allowPrivilegeEscalation == false
	msg := sprintf("container <%v> must set allowPrivilegeEscalation=false", [c.name])
}

violation contains {"msg": msg} if {
	spec := workload.pod_spec(input.review.object)
	some f in ["hostPID", "hostIPC", "hostNetwork"]
	spec[f] == true
	msg := sprintf("pod must not set %v=true", [f])
}
