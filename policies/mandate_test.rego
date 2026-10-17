package mandate_test

import data.mandate

tok := {
	"sub": "alice@corp.com",
	"act": {"sub": "agent:summarizer"},
	"task": "t_1",
	"exp": 2000,
	"scope": [
		{"tool": "email.send", "constraints": {"domains": ["corp.com"], "max_calls": 2, "max_recipients": 3}},
		{"tool": "fs.read", "constraints": {"path_prefix": "/ws/t_1"}},
		{"tool": "http.request", "constraints": {"domains": ["api.github.com"], "methods": ["GET"]}},
	],
}

base := {"token": tok, "usage": {}, "now": 1000}

test_email_allowed if {
	mandate.decision.allow with input as object.union(base, {"tool": "email.send", "parsed": {"recipients": [{"domain": "corp.com"}]}})
}

test_email_external_denied if {
	d := mandate.decision with input as object.union(base, {"tool": "email.send", "parsed": {"recipients": [{"domain": "corp.com"}, {"domain": "evil.com"}]}})
	not d.allow
	"recipient domain evil.com not in grant" in d.reasons
}

test_email_lookalike_subdomain_denied if {
	not mandate.allow with input as object.union(base, {"tool": "email.send", "parsed": {"recipients": [{"domain": "corp.com.evil.io"}]}})
}

test_email_budget if {
	not mandate.allow with input as object.union(base, {"tool": "email.send", "usage": {"email.send": 2}, "parsed": {"recipients": [{"domain": "corp.com"}]}})
}

test_tool_not_granted if {
	d := mandate.decision with input as object.union(base, {"tool": "fs.write", "parsed": {"path": "/ws/t_1/a"}})
	not d.allow
	"tool fs.write not in grant" in d.reasons
}

test_fs_prefix_trick_denied if {
	not mandate.allow with input as object.union(base, {"tool": "fs.read", "parsed": {"path": "/ws/t_10/secret"}})
}

test_fs_inside_allowed if {
	mandate.allow with input as object.union(base, {"tool": "fs.read", "parsed": {"path": "/ws/t_1/notes.md"}})
}

test_http_post_denied if {
	not mandate.allow with input as object.union(base, {"tool": "http.request", "parsed": {"host": "api.github.com", "scheme": "https", "method": "POST"}})
}

test_http_http_scheme_denied if {
	not mandate.allow with input as object.union(base, {"tool": "http.request", "parsed": {"host": "api.github.com", "scheme": "http", "method": "GET"}})
}

test_expired if {
	not mandate.allow with input as object.union(base, {"now": 3000, "tool": "fs.read", "parsed": {"path": "/ws/t_1/a"}})
}
