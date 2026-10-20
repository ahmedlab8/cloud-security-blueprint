package k8srequireresourcelimits

import rego.v1

# Shared helpers are shipped to Gatekeeper via the template's `libs` field.
import data.lib.workload

required := ["cpu", "memory"]

violation contains {"msg": msg} if {
	some c in workload.containers(input.review.object)
	some r in required
	not c.resources.limits[r]
	msg := sprintf("container <%v> must define resources.limits.%v", [c.name, r])
}

violation contains {"msg": msg} if {
	some c in workload.containers(input.review.object)
	some r in required
	not c.resources.requests[r]
	msg := sprintf("container <%v> must define resources.requests.%v", [c.name, r])
}
