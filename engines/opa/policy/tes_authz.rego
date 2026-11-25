# Reference TES AuthZ policy (tes-authzen/1 to /3), spec draft 3, sections 7,
# 12 and 13: owner only.
#
# Input: one AuthZEN 1.0 Access Evaluation request, unchanged.
# Data:  data.tes_authz, loaded from config/reference-policy.json:
#   entitlement_claim  claim in subject.properties.claims holding entitlements
#   members            {values: exact entitlements, prefixes: raw string prefixes}
#                      of the entitlement that may create tasks
#   service_clients    optional list of {iss, client_id}: service clients that
#                      may create tasks without the entitlement (spec section 7)
#   image_prefixes     allowed executor image prefixes; empty = any image
#   services           service-info IDs this policy answers for
#
# Rules:
#   CreateTask on tes_task_set:own   member or listed service client, and
#                                    every executor image allowed; under
#                                    tes-authzen/3 the request names the
#                                    caller as resource owner
#   GetTask, CancelTask on tes_task  resource owner == subject.id, also after
#                                    the entitlement is revoked; a missing or
#                                    empty owner: nobody
#   ListTasks on tes_task_set:own    any caller; a plain allow is the list
#                                    scope "own" (spec section 3.5), so the
#                                    TES lists the caller's tasks only
# There is no admin: nobody reads, lists or cancels another owner's tasks,
# whatever their entitlements, and tes_task_set:all is never allowed (it is
# no longer in the vocabulary from tes-authzen/3 on). A listed service client
# gets the create grant and nothing beyond: it owns its tasks like any
# creator. Leftover policy data with an "admins" key (from before owner
# only) or a malformed service_clients list denies every request. Anything
# else, and any request outside the profiles, is denied (also the
# TES-specific resource types of tes-authzen/2, such as poiesis_api_keys).
package tes.authz

import rego.v1

cfg := data.tes_authz

default allow := false

allow if {
	contract_ok
	input.action.name == "CreateTask"
	input.resource.type == "tes_task_set"
	input.resource.id == "own"
	create_owner_ok
	may_create
	images_ok
}

allow if {
	contract_ok
	input.action.name in {"GetTask", "CancelTask"}
	input.resource.type == "tes_task"
	owns_task
}

allow if {
	contract_ok
	input.action.name == "ListTasks"
	input.resource.type == "tes_task_set"
	input.resource.id == "own"
}

contract_ok if {
	# Policy data from before owner only: deny everything, as the OpenFGA
	# setup job refuses to start, so nobody assumes admins still work.
	not "admins" in object.keys(cfg)
	service_clients_ok
	input.context.tes.profile in {"tes-authzen/1", "tes-authzen/2", "tes-authzen/3"}
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

# tes-authzen/3: CreateTask names the caller as the new task's owner.
create_owner_ok if input.context.tes.profile != "tes-authzen/3"

create_owner_ok if {
	input.context.tes.profile == "tes-authzen/3"
	object.get(input.resource, ["properties", "owner"], null) == input.subject.id
}

# Only CreateTask needs the entitlement; owners keep their tasks without it.
member if entitled(cfg.members)

may_create if member

may_create if listed_client

# Service clients (spec section 7): optional, a list of {iss, client_id}.
service_clients := object.get(cfg, "service_clients", [])

# Every entry has exactly iss and client_id, both non-empty strings of
# printable ASCII without spaces (the OpenFGA setup job refuses the same data), so a
# malformed list fails closed instead of being skipped in parts.
service_clients_ok if {
	is_array(service_clients)
	every c in service_clients {
		is_object(c)
		object.keys(c) == {"iss", "client_id"}
		plain_id(c.iss)
		plain_id(c.client_id)
	}
}

plain_id(x) if {
	is_string(x)
	regex.match(`^[!-~]+$`, x)
}

# A client-credentials caller listed by issuer and client ID: sub equals the
# client ID (LS Login client tokens), so a user token issued to that client
# (same client_id, the user's sub) doesn't count. Exact string comparison.
listed_client if {
	props := input.subject.properties
	is_string(props.iss)
	is_string(props.client_id)
	props.sub == props.client_id
	some c in service_clients
	c.iss == props.iss
	c.client_id == props.client_id
}

# The caller owns the task: a non-empty string owner equal to subject.id.
owns_task if {
	owner := object.get(input.resource, ["properties", "owner"], "")
	is_string(owner)
	owner != ""
	owner == input.subject.id
}

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
