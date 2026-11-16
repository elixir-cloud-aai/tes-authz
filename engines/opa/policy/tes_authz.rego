# Reference TES AuthZ policy (tes-authzen/1), spec draft 3, section 7.
#
# Input: one AuthZEN 1.0 Access Evaluation request, unchanged.
# Data:  data.tes_authz, loaded from config/reference-policy.json:
#   entitlement_claim  claim in subject.properties.claims holding entitlements
#   members, admins    {values: exact entitlements, prefixes: raw string prefixes}
#   image_prefixes     allowed executor image prefixes; empty = any image
#   services           service-info IDs this policy answers for
#
# Rules:
#   CreateTask on tes_task_set:own   member, and every executor image allowed
#   GetTask, CancelTask on tes_task  resource owner == subject.id, or admin;
#                                    missing or empty owner: admins only
#   ListTasks on tes_task_set:own    member
#   ListTasks on tes_task_set:all    admin
# Anything else, and any request outside the profile, is denied.
package tes.authz

import rego.v1

cfg := data.tes_authz

default allow := false

allow if {
	contract_ok
	input.action.name == "CreateTask"
	input.resource.type == "tes_task_set"
	input.resource.id == "own"
	member
	images_ok
}

allow if {
	contract_ok
	input.action.name in {"GetTask", "CancelTask"}
	input.resource.type == "tes_task"
	owner_or_admin
}

allow if {
	contract_ok
	input.action.name == "ListTasks"
	input.resource.type == "tes_task_set"
	input.resource.id == "own"
	member
}

allow if {
	contract_ok
	input.action.name == "ListTasks"
	input.resource.type == "tes_task_set"
	input.resource.id == "all"
	admin
}

contract_ok if {
	input.context.tes.profile == "tes-authzen/1"
	input.context.tes.service_id in cfg.services
	input.subject.type == "user"
	is_string(input.subject.id)
	input.subject.id != ""
	is_string(input.resource.id)
	input.resource.id != ""
	properties_ok(input.subject)
	properties_ok(input.action)
	properties_ok(input.resource)
}

# Properties are optional, but must be an object when present.
properties_ok(x) if not "properties" in object.keys(x)

properties_ok(x) if is_object(x.properties)

# Entitlements as a list of strings: a string claim counts as one value,
# non-string list elements and other types are ignored.
entitlements := [v] if {
	v := object.get(input.subject, ["properties", "claims", cfg.entitlement_claim], null)
	is_string(v)
}

entitlements := [e | some e in v; is_string(e)] if {
	v := object.get(input.subject, ["properties", "claims", cfg.entitlement_claim], null)
	is_array(v)
}

default entitlements := []

entitled(group) if {
	some e in entitlements
	e in group.values
}

entitled(group) if {
	some e in entitlements
	some p in group.prefixes
	startswith(e, p)
}

member if entitled(cfg.members)

admin if entitled(cfg.admins)

owner_or_admin if {
	owner := object.get(input.resource, ["properties", "owner"], "")
	is_string(owner)
	owner != ""
	owner == input.subject.id
}

owner_or_admin if admin

images_ok if count(cfg.image_prefixes) == 0

# With an allowlist, task.executors must be an array of objects whose
# images all match; a missing or malformed task or executor list is denied.
images_ok if {
	count(cfg.image_prefixes) > 0
	executors := object.get(input.resource, ["properties", "task", "executors"], null)
	is_array(executors)
	every ex in executors {
		is_object(ex)
		image := object.get(ex, "image", null)
		is_string(image)
		some p in cfg.image_prefixes
		startswith(image, p)
	}
}
