# Tests of the API policy (`authz.rego`), run by `scripts/test-image.sh`
# with the OPA of the image (`opa test`). Not in the image (`.dockerignore`)
package system.authz_test

import data.system.authz

decision := ["v1", "data", "tes", "authz", "allow"]

test_decision_query_allowed if {
	authz.allow with input as {"method": "POST", "path": decision}
}

test_health_allowed if {
	authz.allow with input as {"method": "GET", "path": ["health"]}
}

test_decision_query_by_get_denied if {
	not authz.allow with input as {"method": "GET", "path": decision}
}

test_policy_write_denied if {
	not authz.allow with input as {"method": "PUT", "path": ["v1", "policies", "x"]}
}

test_data_write_denied if {
	not authz.allow with input as {"method": "PUT", "path": ["v1", "data", "tes_authz"]}
	not authz.allow with input as {"method": "PATCH", "path": ["v1", "data"]}
	not authz.allow with input as {"method": "DELETE", "path": ["v1", "data", "tes_authz"]}
}

test_data_read_denied if {
	not authz.allow with input as {"method": "GET", "path": ["v1", "data"]}
	not authz.allow with input as {"method": "POST", "path": ["v1", "data", "tes_authz"]}
	not authz.allow with input as {"method": "POST", "path": ["v1", "data", "tes", "authz"]}
}

test_other_apis_denied if {
	not authz.allow with input as {"method": "POST", "path": ["v1", "query"]}
	not authz.allow with input as {"method": "POST", "path": ["v1", "compile"]}
	not authz.allow with input as {"method": "GET", "path": ["v1", "config"]}
	not authz.allow with input as {"method": "GET", "path": ["v1", "status"]}
	not authz.allow with input as {"method": "POST", "path": []}
}

test_longer_decision_path_denied if {
	not authz.allow with input as {"method": "POST", "path": array.concat(decision, ["x"])}
}

test_decision_query_with_parameters_denied if {
	not authz.allow with input as {"method": "POST", "path": decision, "params": {"explain": ["full"]}}
	not authz.allow with input as {"method": "POST", "path": decision, "params": {"provenance": [""]}}
}

test_decision_query_with_empty_parameters_allowed if {
	authz.allow with input as {"method": "POST", "path": decision, "params": {}}
}
