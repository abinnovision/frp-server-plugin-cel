package policy_test

import (
	"log/slog"
	"strings"
	"testing"

	"github.com/abinnovision/frp-server-plugin-cel/internal/config"
	"github.com/abinnovision/frp-server-plugin-cel/internal/policy"
)

func discard() *slog.Logger { return slog.New(slog.DiscardHandler) }

func mustEngine(t *testing.T, cfg *config.Config) *policy.Engine {
	t.Helper()
	// The engine defaults DefaultAction and per-rule OnError itself; only
	// set the reject reason here since TestDefaultReject depends on it.
	if cfg.DefaultRejectReason == "" {
		cfg.DefaultRejectReason = "rejected by default policy"
	}
	e, err := policy.New(cfg, discard())
	if err != nil {
		t.Fatalf("policy.New: %v", err)
	}
	return e
}

// newProxyContent mirrors frps's msg.NewProxy JSON shape.
func newProxyContent(domains ...any) map[string]any {
	return map[string]any{
		"user":           map[string]any{"user": "andre", "metas": map[string]any{"team": "dev"}},
		"proxy_name":     "web",
		"proxy_type":     "http",
		"custom_domains": domains,
	}
}

const domainWhen = `has(content.custom_domains) && !content.custom_domains.all(d, d.endsWith(".tunnels.example.com"))`

func TestRejectOutsideDomainSuffix(t *testing.T) {
	e := mustEngine(t, &config.Config{Rules: []config.Rule{{
		Name: "domains", Ops: []string{"NewProxy"}, When: domainWhen,
		Action: "reject", Reason: "custom_domains must be under *.tunnels.example.com",
	}}})
	d := e.Evaluate("NewProxy", newProxyContent("evil.example.com"))
	if d.Action != policy.ActionReject || !strings.Contains(d.Reason, "tunnels.example.com") {
		t.Fatalf("got %+v, want reject", d)
	}
	d = e.Evaluate("NewProxy", newProxyContent("ok.tunnels.example.com"))
	if d.Action != policy.ActionAllow || d.Rule != "default" {
		t.Fatalf("got %+v, want default allow", d)
	}
}

func TestOpsFiltering(t *testing.T) {
	e := mustEngine(t, &config.Config{Rules: []config.Rule{{
		Name: "r", Ops: []string{"Login"}, When: "true", Action: "reject", Reason: "no",
	}}})
	if d := e.Evaluate("NewProxy", map[string]any{}); d.Action != policy.ActionAllow {
		t.Fatalf("rule for Login must not fire for NewProxy: %+v", d)
	}
}

func TestFirstMatchWins(t *testing.T) {
	e := mustEngine(t, &config.Config{Rules: []config.Rule{
		{Name: "first", Ops: []string{"Ping"}, When: "true", Action: "allow"},
		{Name: "second", Ops: []string{"Ping"}, When: "true", Action: "reject", Reason: "no"},
	}})
	if d := e.Evaluate("Ping", map[string]any{}); d.Rule != "first" || d.Action != policy.ActionAllow {
		t.Fatalf("got %+v, want first/allow", d)
	}
}

func TestDefaultReject(t *testing.T) {
	e := mustEngine(t, &config.Config{DefaultAction: "reject"})
	d := e.Evaluate("NewProxy", map[string]any{})
	if d.Action != policy.ActionReject || d.Reason != "rejected by default policy" {
		t.Fatalf("got %+v", d)
	}
}

func TestRewriteMergesOntoOriginal(t *testing.T) {
	e := mustEngine(t, &config.Config{Rules: []config.Rule{{
		Name: "bw", Ops: []string{"NewProxy"}, When: `content.user.user == 'ci-bot'`,
		Action: "rewrite", Content: `{"bandwidth_limit": "1MB"}`, // bare partial map on purpose
	}}})
	content := newProxyContent("a.tunnels.example.com")
	content["user"] = map[string]any{"user": "ci-bot"}
	d := e.Evaluate("NewProxy", content)
	if d.Action != policy.ActionRewrite {
		t.Fatalf("got %+v, want rewrite", d)
	}
	if d.Content["bandwidth_limit"] != "1MB" {
		t.Errorf("bandwidth_limit not set: %#v", d.Content)
	}
	if d.Content["proxy_name"] != "web" {
		t.Errorf("server-side merge must preserve omitted fields: %#v", d.Content)
	}
}

func TestEvalErrorOnRejectRuleFailsClosed(t *testing.T) {
	e := mustEngine(t, &config.Config{Rules: []config.Rule{{
		// content.custom_domains is a string here -> .all() errors at runtime
		Name: "domains", Ops: []string{"NewProxy"},
		When:   `!content.custom_domains.all(d, d.endsWith(".tunnels.example.com"))`,
		Action: "reject", Reason: "bad domains",
	}}})
	d := e.Evaluate("NewProxy", map[string]any{"custom_domains": "not-a-list"})
	if d.Action != policy.ActionReject {
		t.Fatalf("eval error on reject rule must fail closed, got %+v", d)
	}
}

func TestEvalErrorWithSkipContinues(t *testing.T) {
	e := mustEngine(t, &config.Config{Rules: []config.Rule{
		{Name: "broken", Ops: []string{"Ping"}, When: `content.nope.deeper == 1`,
			Action: "reject", Reason: "x", OnError: "skip"},
		{Name: "fallback", Ops: []string{"Ping"}, When: "true", Action: "reject", Reason: "fell through"},
	}})
	d := e.Evaluate("Ping", map[string]any{})
	if d.Rule != "fallback" {
		t.Fatalf("skip must continue down the chain, got %+v", d)
	}
}

func TestNilContentBehavesAsEmptyMap(t *testing.T) {
	e := mustEngine(t, &config.Config{Rules: []config.Rule{{
		Name: "r", Ops: []string{"Ping"}, When: `has(content.user)`, Action: "reject", Reason: "x",
	}}})
	if d := e.Evaluate("Ping", nil); d.Action != policy.ActionAllow {
		t.Fatalf("nil content: has() must be false, got %+v", d)
	}
}

func TestCompileErrorNamesRule(t *testing.T) {
	_, err := policy.New(&config.Config{DefaultAction: "allow", Rules: []config.Rule{{
		Name: "syntax-err", Ops: []string{"Ping"}, When: "this is not CEL ((", Action: "allow", OnError: "skip",
	}}}, discard())
	if err == nil || !strings.Contains(err.Error(), "syntax-err") {
		t.Fatalf("compile error must name the rule, got %v", err)
	}
}

func TestNewErrorsOnUnknownActionNamingRule(t *testing.T) {
	_, err := policy.New(&config.Config{Rules: []config.Rule{{
		Name: "bogus-action", Ops: []string{"Ping"}, When: "true", Action: "delete",
	}}}, discard())
	if err == nil || !strings.Contains(err.Error(), "bogus-action") {
		t.Fatalf("unknown action must produce an error naming the rule, got %v", err)
	}
}

// TestRejectRuleEmptyOnErrorFailsClosed verifies the engine itself (not
// config.Load's defaulting) guarantees a reject rule with an unset
// OnError fails closed on an evaluation error.
func TestRejectRuleEmptyOnErrorFailsClosed(t *testing.T) {
	e, err := policy.New(&config.Config{Rules: []config.Rule{{
		// content.custom_domains is a string here -> .all() errors at runtime
		Name: "domains", Ops: []string{"NewProxy"},
		When:   `!content.custom_domains.all(d, d.endsWith(".tunnels.example.com"))`,
		Action: "reject", Reason: "bad domains",
		// OnError intentionally left empty.
	}}}, discard())
	if err != nil {
		t.Fatalf("policy.New: %v", err)
	}
	d := e.Evaluate("NewProxy", map[string]any{"custom_domains": "not-a-list"})
	if d.Action != policy.ActionReject {
		t.Fatalf("reject rule with empty OnError must fail closed, got %+v", d)
	}
}
