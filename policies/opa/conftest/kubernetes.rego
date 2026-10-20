# Shift-left: run the exact Gatekeeper policies against raw manifests in CI with conftest,
# so violations fail the pull request instead of the deployment.
package main

import rego.v1

import data.k8sblockprivilegedcontainers
import data.k8sblockpublicloadbalancer
import data.k8sblockrootcontainers
import data.k8sdisallowlatesttag
import data.k8srequireresourcelimits

review := {"review": {"object": input}, "parameters": {}}

deny contains msg if {
	some v in k8sblockrootcontainers.violation with input as review
	msg := sprintf("[block-root] %v", [v.msg])
}

deny contains msg if {
	some v in k8sblockprivilegedcontainers.violation with input as review
	msg := sprintf("[block-privileged] %v", [v.msg])
}

deny contains msg if {
	some v in k8sdisallowlatesttag.violation with input as review
	msg := sprintf("[disallow-latest] %v", [v.msg])
}

deny contains msg if {
	some v in k8srequireresourcelimits.violation with input as review
	msg := sprintf("[require-limits] %v", [v.msg])
}

deny contains msg if {
	some v in k8sblockpublicloadbalancer.violation with input as review
	msg := sprintf("[block-public-lb] %v", [v.msg])
}
