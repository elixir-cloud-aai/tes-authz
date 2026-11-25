# Authorization of OPA's own API in the decision service image
# (`Dockerfile`, `shims/opa_service.py`, which starts OPA with
# `--authorization=basic`). OPA listens on loopback, but in a pod every
# container shares that loopback: without this policy, any of them could
# replace the policy or the data (`PUT /v1/policies`, `PUT /v1/data`) or
# read the data. Only the front's decision query and the health check are
# allowed.
package system.authz

default allow := false

# The decision the front asks for (`opa_front.DECISION_PATH`), without
# query parameters: `?explain`, `?provenance`, `?metrics` and the like
# would return traces with the data, or more than the decision
allow if {
	input.method == "POST"
	input.path == ["v1", "data", "tes", "authz", "allow"]
	count(object.get(input, "params", {})) == 0
}

# The health check of the entry point and of probes
allow if {
	input.method == "GET"
	input.path == ["health"]
}
