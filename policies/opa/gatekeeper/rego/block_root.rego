package k8sblockrootcontainers

import rego.v1

# Shared helpers are shipped to Gatekeeper via the template's `libs` field.
import data.lib.workload

violation contains {"msg": msg} if {
	spec := workload.pod_spec(input.review.object)
	some c in workload.containers(input.review.object)
	not runs_as_non_root(spec, c)
	msg := sprintf("container <%v> must set runAsNonRoot=true (or a non-zero runAsUser) at pod or container level", [c.name])
}

violation contains {"msg": msg} if {
	some c in workload.containers(input.review.object)
	c.securityContext.runAsUser == 0
	msg := sprintf("container <%v> explicitly runs as UID 0 (root)", [c.name])
}

violation contains {"msg": msg} if {
	spec := workload.pod_spec(input.review.object)
	spec.securityContext.runAsUser == 0
	msg := "pod securityContext explicitly runs as UID 0 (root)"
}

runs_as_non_root(_, c) if c.securityContext.runAsNonRoot == true

runs_as_non_root(spec, c) if {
	not has_key(object.get(c, "securityContext", {}), "runAsNonRoot")
	spec.securityContext.runAsNonRoot == true
}

runs_as_non_root(_, c) if c.securityContext.runAsUser > 0

runs_as_non_root(spec, c) if {
	not has_key(object.get(c, "securityContext", {}), "runAsUser")
	spec.securityContext.runAsUser > 0
}

has_key(o, k) if _ = o[k]
