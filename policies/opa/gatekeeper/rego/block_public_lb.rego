package k8sblockpublicloadbalancer

import rego.v1

# Annotation/value pairs that make a LoadBalancer Service internal on each cloud.
internal_annotations := {
	"service.beta.kubernetes.io/aws-load-balancer-internal": "true",
	"service.beta.kubernetes.io/aws-load-balancer-scheme": "internal",
	"service.beta.kubernetes.io/azure-load-balancer-internal": "true",
	"networking.gke.io/load-balancer-type": "Internal",
}

violation contains {"msg": msg} if {
	svc := input.review.object
	svc.kind == "Service"
	svc.spec.type == "LoadBalancer"
	not is_internal(svc)
	msg := sprintf("Service <%v> of type LoadBalancer must be internal (set an internal-LB annotation); expose apps through the ingress/WAF tier", [svc.metadata.name])
}

is_internal(svc) if {
	some k, v in internal_annotations
	lower(object.get(object.get(svc.metadata, "annotations", {}), k, "")) == lower(v)
}
