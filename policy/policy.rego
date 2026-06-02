package zerotrust.authz

default allow := false

roles := {role | role := input.roles[_]}
scopes := {scope | scope := input.scopes[_]}

allow if {
	input.method == "GET"
	startswith(input.path, "/users")
	"user" in roles
}

allow if {
	input.method == "GET"
	startswith(input.path, "/resources")
	"user" in roles
}

allow if {
	input.method == "POST"
	input.path == "/resources"
	"user" in roles
	"resource:write" in scopes
}

allow if {
	startswith(input.path, "/admin")
	"admin" in roles
}

deny_reason := "no matching allow rule" if {
	not allow
}
