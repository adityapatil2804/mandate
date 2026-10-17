# Mandate authorization policy.
#
# Input (built by the gateway from TRUSTED, parsed data only; never raw model text):
#   token:  verified claims {sub, act, task, scope: [{tool, constraints}], exp}
#   tool:   tool name
#   parsed: structured args produced by the gateway's parsers
#   usage:  {tool: calls already allowed in this task}
#   now:    unix seconds
#
# Output: data.mandate.decision = {"allow": bool, "reasons": [string]}
package mandate

default allow := false

grants := [g | some g in input.token.scope; g.tool == input.tool]

# The broker guarantees at most one grant per tool, so `g` is that grant.
g := grants[0] if count(grants) == 1

allow if {
	count(grants) == 1
	count(deny) == 0
}

decision := {"allow": allow, "reasons": sort(deny)}

# ---------- generic rules ----------

deny contains sprintf("tool %s not in grant", [input.tool]) if count(grants) == 0

deny contains "token expired" if input.now >= input.token.exp

deny contains msg if {
	max := g.constraints.max_calls
	object.get(input.usage, input.tool, 0) >= max
	msg := sprintf("call budget exhausted for %s (max %d)", [input.tool, max])
}

# ---------- email.send ----------

deny contains msg if {
	input.tool == "email.send"
	some r in input.parsed.recipients
	not r.domain in g.constraints.domains
	msg := sprintf("recipient domain %s not in grant", [r.domain])
}

deny contains msg if {
	input.tool == "email.send"
	max := g.constraints.max_recipients
	count(input.parsed.recipients) > max
	msg := sprintf("too many recipients (%d > %d)", [count(input.parsed.recipients), max])
}

# ---------- fs.read / fs.write ----------

fs_tools := {"fs.read", "fs.write", "fs.list"}

deny contains msg if {
	input.tool in fs_tools
	not path_within(input.parsed.path, g.constraints.path_prefix)
	msg := sprintf("path %s outside task directory", [input.parsed.path])
}

path_within(p, prefix) if p == prefix

path_within(p, prefix) if startswith(p, concat("", [prefix, "/"]))

# ---------- http.request ----------

deny contains msg if {
	input.tool == "http.request"
	not input.parsed.host in g.constraints.domains
	msg := sprintf("host %s not in domain allowlist", [input.parsed.host])
}

deny contains msg if {
	input.tool == "http.request"
	input.parsed.scheme != "https"
	msg := sprintf("scheme %s not allowed", [input.parsed.scheme])
}

deny contains msg if {
	input.tool == "http.request"
	not input.parsed.method in g.constraints.methods
	msg := sprintf("method %s not allowed", [input.parsed.method])
}
