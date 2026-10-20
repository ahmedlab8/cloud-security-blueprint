package k8sdisallowlatesttag

import rego.v1

# Shared helpers are shipped to Gatekeeper via the template's `libs` field.
import data.lib.workload

violation contains {"msg": msg} if {
	some c in workload.containers(input.review.object)
	not pinned(c.image)
	msg := sprintf("container <%v> image <%v> must use an explicit, non-latest tag or a digest", [c.name, c.image])
}

# Digest-pinned images are always acceptable.
pinned(image) if contains(image, "@sha256:")

pinned(image) if {
	not contains(image, "@")
	tag := image_tag(image)
	tag != ""
	tag != "latest"
}

# The tag is whatever follows the last ":" after the last "/" (ports in registry hosts are ignored).
image_tag(image) := tag if {
	parts := split(image, "/")
	last := parts[count(parts) - 1]
	contains(last, ":")
	tag := split(last, ":")[1]
}

image_tag(image) := "" if {
	parts := split(image, "/")
	not contains(parts[count(parts) - 1], ":")
}
