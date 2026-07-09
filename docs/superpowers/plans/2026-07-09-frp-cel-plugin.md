# frp-server-plugin-cel Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** A standalone Go service implementing frp's server plugin HTTP protocol that decides allow/reject/rewrite per lifecycle op via user-configured CEL rules.

**Architecture:** Single binary. `internal/config` parses YAML and validates it against an embedded JSON Schema; `internal/policy` compiles CEL at startup and evaluates ordered first-match-wins rules; `internal/server` maps decisions to frp's response envelope. Releases via GoReleaser (multi-arch GHCR images).

**Tech Stack:** Go ≥1.24, `github.com/google/cel-go`, `gopkg.in/yaml.v3`, `github.com/santhosh-tekuri/jsonschema/v6`, GoReleaser v2, distroless/static.

**Spec:** `docs/superpowers/specs/2026-07-09-frp-cel-plugin-design.md` — read it before starting any task.

## Global Constraints

- Module path: `github.com/abinnovision/frp-server-plugin-cel`. Binary name: `frp-cel-plugin`.
- Only three direct dependencies: `cel-go`, `yaml.v3`, `jsonschema/v6`.
- Defaults: `bind: ":9001"`, `path: "/handler"`, `defaultAction: allow`, default reject reason `"rejected by default policy"`.
- `onError` defaults: `reject` when `action: reject`, else `skip`. An eval error on a reject rule MUST fail closed.
- Rewrite decisions MUST shallow-merge the CEL result onto the original content server-side (omitted fields preserved).
- frp response envelopes (exact): allow `{"reject":false,"unchange":true}` (no `content` key); reject `{"reject":true,"reject_reason":"..."}`; rewrite `{"reject":false,"unchange":false,"content":{...}}`.
- HTTP 400 for malformed body or missing `op` query param (frps treats non-200 as reject).
- `CloseProxy` reject/rewrite rules are ineffective in frps → config loader surfaces a warning, does not error.
- Commit messages: semantic (`feat:`, `fix:`, `docs:`, `test:`, `build:`). NEVER add Co-Authored-By or similar trailers.
- Structured logging via `log/slog` JSON only. No other logging library.

---

### Task 1: Module scaffolding, JSON Schema, config package

**Files:**
- Create: `go.mod` (via `go mod init`)
- Create: `schema.go` (repo root — embeds the schema; `go:embed` cannot reach parent dirs from `internal/config`)
- Create: `config.schema.json`
- Create: `internal/config/config.go`
- Test: `internal/config/config_test.go`

**Interfaces:**
- Consumes: nothing (first task).
- Produces: `config.Load(path string) (*Config, error)`; types `config.Config{Bind, Path, DefaultAction, DefaultRejectReason string; Rules []Rule}` and `config.Rule{Name string; Ops []string; When, Action, Reason, Content, OnError string}`; `(*Config).Lint() []string` returning human-readable warnings. Root package exports `frpcelplugin.ConfigSchema []byte`.

- [ ] **Step 1: Initialize module and fetch dependencies**

```bash
cd /Users/aloreth/dev/projects/frp-server-plugin-cel
go mod init github.com/abinnovision/frp-server-plugin-cel
go get github.com/google/cel-go gopkg.in/yaml.v3 github.com/santhosh-tekuri/jsonschema/v6
```

Expected: `go.mod` and `go.sum` created without errors.

- [ ] **Step 2: Write the JSON Schema**

Create `config.schema.json`:

```json
{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "$id": "https://github.com/abinnovision/frp-server-plugin-cel/config.schema.json",
  "title": "frp-cel-plugin configuration",
  "type": "object",
  "additionalProperties": false,
  "properties": {
    "bind": { "type": "string", "default": ":9001" },
    "path": { "type": "string", "default": "/handler" },
    "defaultAction": { "enum": ["allow", "reject"], "default": "allow" },
    "defaultRejectReason": { "type": "string", "default": "rejected by default policy" },
    "rules": {
      "type": "array",
      "items": { "$ref": "#/$defs/rule" }
    }
  },
  "$defs": {
    "rule": {
      "type": "object",
      "additionalProperties": false,
      "required": ["name", "ops", "when", "action"],
      "properties": {
        "name": { "type": "string", "minLength": 1 },
        "ops": { "type": "array", "items": { "type": "string", "minLength": 1 }, "minItems": 1 },
        "when": { "type": "string", "minLength": 1, "description": "CEL expression evaluating to bool" },
        "action": { "enum": ["allow", "reject", "rewrite"] },
        "reason": { "type": "string", "minLength": 1 },
        "content": { "type": "string", "minLength": 1, "description": "CEL expression evaluating to a map; required for rewrite" },
        "onError": { "enum": ["skip", "reject"] }
      },
      "allOf": [
        {
          "if": { "properties": { "action": { "const": "reject" } } },
          "then": { "required": ["reason"] }
        },
        {
          "if": { "properties": { "action": { "const": "rewrite" } } },
          "then": { "required": ["content"] }
        }
      ]
    }
  }
}
```

Create `schema.go` at the repo root:

```go
// Package frpcelplugin holds root-level embedded assets.
package frpcelplugin

import _ "embed"

// ConfigSchema is the JSON Schema (draft 2020-12) for the YAML config file.
//
//go:embed config.schema.json
var ConfigSchema []byte
```

- [ ] **Step 3: Write the failing config tests**

Create `internal/config/config_test.go`:

```go
package config_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/abinnovision/frp-server-plugin-cel/internal/config"
)

func writeConfig(t *testing.T, yaml string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(path, []byte(yaml), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

const validYAML = `
rules:
  - name: restrict-custom-domains
    ops: [NewProxy]
    when: |
      has(content.custom_domains) &&
      !content.custom_domains.all(d, d.endsWith(".tunnels.example.com"))
    action: reject
    reason: "custom_domains must be under *.tunnels.example.com"
  - name: force-ci-bandwidth-limit
    ops: [NewProxy]
    when: "content.user.user == 'ci-bot'"
    action: rewrite
    content: 'content.with({"bandwidth_limit": "1MB"})'
`

func TestLoadValidAppliesDefaults(t *testing.T) {
	cfg, err := config.Load(writeConfig(t, validYAML))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.Bind != ":9001" || cfg.Path != "/handler" {
		t.Errorf("defaults not applied: bind=%q path=%q", cfg.Bind, cfg.Path)
	}
	if cfg.DefaultAction != "allow" {
		t.Errorf("defaultAction = %q, want allow", cfg.DefaultAction)
	}
	if cfg.DefaultRejectReason != "rejected by default policy" {
		t.Errorf("defaultRejectReason = %q", cfg.DefaultRejectReason)
	}
	if len(cfg.Rules) != 2 {
		t.Fatalf("rules = %d, want 2", len(cfg.Rules))
	}
	if cfg.Rules[0].OnError != "reject" {
		t.Errorf("reject rule onError default = %q, want reject", cfg.Rules[0].OnError)
	}
	if cfg.Rules[1].OnError != "skip" {
		t.Errorf("rewrite rule onError default = %q, want skip", cfg.Rules[1].OnError)
	}
}

func TestLoadRejectsUnknownKey(t *testing.T) {
	_, err := config.Load(writeConfig(t, "listen: ':9001'\nrules: []\n"))
	if err == nil || !strings.Contains(err.Error(), "schema") {
		t.Fatalf("want schema error, got %v", err)
	}
}

func TestLoadRejectsRejectRuleWithoutReason(t *testing.T) {
	_, err := config.Load(writeConfig(t, `
rules:
  - name: r1
    ops: [NewProxy]
    when: "true"
    action: reject
`))
	if err == nil {
		t.Fatal("want error for reject rule without reason")
	}
}

func TestLoadRejectsDuplicateRuleNames(t *testing.T) {
	_, err := config.Load(writeConfig(t, `
rules:
  - { name: dup, ops: [Ping], when: "true", action: allow }
  - { name: dup, ops: [Ping], when: "true", action: allow }
`))
	if err == nil || !strings.Contains(err.Error(), "dup") {
		t.Fatalf("want duplicate-name error naming the rule, got %v", err)
	}
}

func TestLintWarnsOnCloseProxyRejectRule(t *testing.T) {
	cfg, err := config.Load(writeConfig(t, `
rules:
  - { name: cp, ops: [CloseProxy], when: "true", action: reject, reason: "nope" }
`))
	if err != nil {
		t.Fatal(err)
	}
	warnings := cfg.Lint()
	if len(warnings) != 1 || !strings.Contains(warnings[0], "CloseProxy") {
		t.Fatalf("want one CloseProxy warning, got %v", warnings)
	}
}
```

- [ ] **Step 4: Run tests to verify they fail**

Run: `go test ./internal/config/`
Expected: FAIL (package does not exist / undefined `config.Load`).

- [ ] **Step 5: Implement the config package**

Create `internal/config/config.go`:

```go
// Package config loads and validates the plugin's YAML configuration.
package config

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"

	"github.com/santhosh-tekuri/jsonschema/v6"
	"gopkg.in/yaml.v3"

	root "github.com/abinnovision/frp-server-plugin-cel"
)

// Rule is one policy rule. CEL expressions are kept as source strings;
// compilation happens in internal/policy at engine construction.
type Rule struct {
	Name    string   `yaml:"name"`
	Ops     []string `yaml:"ops"`
	When    string   `yaml:"when"`
	Action  string   `yaml:"action"` // allow | reject | rewrite
	Reason  string   `yaml:"reason"`
	Content string   `yaml:"content"`
	OnError string   `yaml:"onError"` // skip | reject
}

type Config struct {
	Bind                string `yaml:"bind"`
	Path                string `yaml:"path"`
	DefaultAction       string `yaml:"defaultAction"`
	DefaultRejectReason string `yaml:"defaultRejectReason"`
	Rules               []Rule `yaml:"rules"`
}

// Load reads, schema-validates, and decodes the YAML config at path.
func Load(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read config: %w", err)
	}
	if err := validateSchema(data); err != nil {
		return nil, err
	}
	var cfg Config
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("decode config: %w", err)
	}
	applyDefaults(&cfg)
	if err := checkNames(cfg.Rules); err != nil {
		return nil, err
	}
	return &cfg, nil
}

// validateSchema round-trips the YAML document through JSON so the
// validator sees plain JSON value types, then validates it against the
// embedded schema. Structural errors are reported distinctly from CEL
// compile errors (which surface later in internal/policy).
func validateSchema(data []byte) error {
	var raw any
	if err := yaml.Unmarshal(data, &raw); err != nil {
		return fmt.Errorf("parse yaml: %w", err)
	}
	jsonBytes, err := json.Marshal(raw)
	if err != nil {
		return fmt.Errorf("config is not JSON-representable: %w", err)
	}
	doc, err := jsonschema.UnmarshalJSON(bytes.NewReader(jsonBytes))
	if err != nil {
		return fmt.Errorf("parse config document: %w", err)
	}
	schemaDoc, err := jsonschema.UnmarshalJSON(bytes.NewReader(root.ConfigSchema))
	if err != nil {
		return fmt.Errorf("parse embedded schema: %w", err)
	}
	compiler := jsonschema.NewCompiler()
	if err := compiler.AddResource("config.schema.json", schemaDoc); err != nil {
		return fmt.Errorf("register schema: %w", err)
	}
	schema, err := compiler.Compile("config.schema.json")
	if err != nil {
		return fmt.Errorf("compile schema: %w", err)
	}
	if err := schema.Validate(doc); err != nil {
		return fmt.Errorf("config schema validation: %w", err)
	}
	return nil
}

func applyDefaults(cfg *Config) {
	if cfg.Bind == "" {
		cfg.Bind = ":9001"
	}
	if cfg.Path == "" {
		cfg.Path = "/handler"
	}
	if cfg.DefaultAction == "" {
		cfg.DefaultAction = "allow"
	}
	if cfg.DefaultRejectReason == "" {
		cfg.DefaultRejectReason = "rejected by default policy"
	}
	for i := range cfg.Rules {
		if cfg.Rules[i].OnError != "" {
			continue
		}
		if cfg.Rules[i].Action == "reject" {
			cfg.Rules[i].OnError = "reject"
		} else {
			cfg.Rules[i].OnError = "skip"
		}
	}
}

func checkNames(rules []Rule) error {
	seen := map[string]bool{}
	for _, r := range rules {
		if seen[r.Name] {
			return fmt.Errorf("duplicate rule name %q", r.Name)
		}
		seen[r.Name] = true
	}
	return nil
}

// Lint returns non-fatal configuration warnings, e.g. reject/rewrite rules
// targeting CloseProxy (frps discards the plugin response for that op).
func (c *Config) Lint() []string {
	var warnings []string
	for _, r := range c.Rules {
		if r.Action == "allow" {
			continue
		}
		for _, op := range r.Ops {
			if op == "CloseProxy" {
				warnings = append(warnings, fmt.Sprintf(
					"rule %q: frps ignores %s responses for CloseProxy; this rule is observability-only", r.Name, r.Action))
			}
		}
	}
	return warnings
}
```

- [ ] **Step 6: Run tests to verify they pass**

Run: `go test ./internal/config/`
Expected: PASS. If `jsonschema.UnmarshalJSON` or `AddResource` signatures differ from the installed v6 version, check the version's godoc (`go doc github.com/santhosh-tekuri/jsonschema/v6`) and adapt — the flow (unmarshal both docs, add resource, compile, validate) stays the same.

- [ ] **Step 7: Commit**

```bash
git add go.mod go.sum schema.go config.schema.json internal/config/
git commit -m "feat: config loading with embedded JSON Schema validation"
```

---

### Task 2: CEL environment and with() merge function

**Files:**
- Create: `internal/policy/env.go`
- Test: `internal/policy/env_test.go`

**Interfaces:**
- Consumes: nothing from earlier tasks (pure cel-go).
- Produces: `policy.NewEnv() (*cel.Env, error)` — environment with variables `op` (string) and `content` (dyn), the strings extension, and the custom member function `with(map, map) -> map` (shallow merge, overlay wins). Task 3 compiles all rule expressions against this env.

- [ ] **Step 1: Write the failing tests**

Create `internal/policy/env_test.go`:

```go
package policy

import (
	"reflect"
	"testing"
)

// evalExpr compiles and evaluates a CEL expression against the given vars.
func evalExpr(t *testing.T, expr string, vars map[string]any) any {
	t.Helper()
	env, err := NewEnv()
	if err != nil {
		t.Fatalf("NewEnv: %v", err)
	}
	ast, iss := env.Compile(expr)
	if iss.Err() != nil {
		t.Fatalf("compile %q: %v", expr, iss.Err())
	}
	prg, err := env.Program(ast)
	if err != nil {
		t.Fatalf("program: %v", err)
	}
	out, _, err := prg.Eval(vars)
	if err != nil {
		t.Fatalf("eval %q: %v", expr, err)
	}
	native, err := out.ConvertToNative(reflect.TypeOf(map[string]any{}))
	if err == nil {
		return native
	}
	return out.Value()
}

func TestWithMergesShallow(t *testing.T) {
	content := map[string]any{
		"proxy_name":      "web",
		"bandwidth_limit": "",
		"custom_domains":  []any{"a.tunnels.example.com"},
	}
	got := evalExpr(t, `content.with({"bandwidth_limit": "1MB"})`,
		map[string]any{"op": "NewProxy", "content": content})
	want := map[string]any{
		"proxy_name":      "web",
		"bandwidth_limit": "1MB",
		"custom_domains":  []any{"a.tunnels.example.com"},
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("with() = %#v, want %#v", got, want)
	}
}

func TestWithOverlayWins(t *testing.T) {
	got := evalExpr(t, `{"a": 1, "b": 2}.with({"b": 3, "c": 4})`, map[string]any{
		"op": "x", "content": map[string]any{},
	})
	m, ok := got.(map[string]any)
	if !ok {
		t.Fatalf("result is %T, want map", got)
	}
	if m["b"] != int64(3) || m["c"] != int64(4) || m["a"] != int64(1) {
		t.Errorf("merge wrong: %#v", m)
	}
}

func TestBuiltinsAvailable(t *testing.T) {
	content := map[string]any{"custom_domains": []any{"x.tunnels.example.com", "evil.example.com"}}
	got := evalExpr(t,
		`has(content.custom_domains) && !content.custom_domains.all(d, d.endsWith(".tunnels.example.com"))`,
		map[string]any{"op": "NewProxy", "content": content})
	if got != true {
		t.Errorf("flagship expression = %v, want true", got)
	}
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `go test ./internal/policy/`
Expected: FAIL (undefined `NewEnv`).

- [ ] **Step 3: Implement the environment**

Create `internal/policy/env.go`:

```go
// Package policy compiles configured CEL rules and evaluates frp plugin
// requests against them.
package policy

import (
	"fmt"
	"reflect"

	"github.com/google/cel-go/cel"
	"github.com/google/cel-go/common/types"
	"github.com/google/cel-go/common/types/ref"
	"github.com/google/cel-go/ext"
)

// NewEnv builds the CEL environment shared by all rule expressions.
// Exposed variables: op (string), content (dynamic map from the frp
// request). endsWith/startsWith/contains/matches are CEL built-ins; the
// strings extension adds split/join/replace/format etc.
func NewEnv() (*cel.Env, error) {
	return cel.NewEnv(
		cel.Variable("op", cel.StringType),
		cel.Variable("content", cel.DynType),
		ext.Strings(),
		withFunction(),
	)
}

// withFunction registers `base.with(overlay)`: a shallow merge returning
// base with overlay's keys overlaid. It exists because frps replaces the
// proxy content wholesale on rewrite; see the design spec.
func withFunction() cel.EnvOption {
	mapType := cel.MapType(cel.DynType, cel.DynType)
	return cel.Function("with",
		cel.MemberOverload("map_with_map",
			[]*cel.Type{mapType, mapType}, mapType,
			cel.BinaryBinding(func(base, overlay ref.Val) ref.Val {
				bm, err := toStringMap(base)
				if err != nil {
					return types.NewErr("with(): receiver: %v", err)
				}
				om, err := toStringMap(overlay)
				if err != nil {
					return types.NewErr("with(): argument: %v", err)
				}
				merged := make(map[string]any, len(bm)+len(om))
				for k, v := range bm {
					merged[k] = v
				}
				for k, v := range om {
					merged[k] = v
				}
				return types.DefaultTypeAdapter.NativeToValue(merged)
			}),
		),
	)
}

func toStringMap(v ref.Val) (map[string]any, error) {
	native, err := v.ConvertToNative(reflect.TypeOf(map[string]any{}))
	if err != nil {
		return nil, fmt.Errorf("not a string-keyed map: %w", err)
	}
	m, ok := native.(map[string]any)
	if !ok {
		return nil, fmt.Errorf("unexpected native type %T", native)
	}
	return m, nil
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `go test ./internal/policy/`
Expected: PASS. Note: `TestWithOverlayWins` asserts `int64` values — cel-go normalizes integers to int64; if the installed version returns `int` adjust the assertion, not the implementation.

- [ ] **Step 5: Commit**

```bash
git add internal/policy/
git commit -m "feat: CEL environment with custom with() merge function"
```

---

### Task 3: Policy engine

**Files:**
- Create: `internal/policy/engine.go`
- Test: `internal/policy/engine_test.go`

**Interfaces:**
- Consumes: `config.Config`/`config.Rule` (Task 1), `NewEnv()` (Task 2).
- Produces:
  - `type Action string` with constants `ActionAllow Action = "allow"`, `ActionReject Action = "reject"`, `ActionRewrite Action = "rewrite"`.
  - `type Decision struct { Action Action; Reason string; Content map[string]any; Rule string }` (`Rule` is the matched rule name, or `"default"`).
  - `policy.New(cfg *config.Config, logger *slog.Logger) (*Engine, error)` — compiles all CEL, fails fast naming the offending rule.
  - `(*Engine).Evaluate(op string, content map[string]any) Decision` — safe for concurrent use.

- [ ] **Step 1: Write the failing tests**

Create `internal/policy/engine_test.go`:

```go
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
	// Mirror config.Load defaulting for hand-built configs.
	if cfg.DefaultAction == "" {
		cfg.DefaultAction = "allow"
	}
	if cfg.DefaultRejectReason == "" {
		cfg.DefaultRejectReason = "rejected by default policy"
	}
	for i := range cfg.Rules {
		if cfg.Rules[i].OnError == "" {
			if cfg.Rules[i].Action == "reject" {
				cfg.Rules[i].OnError = "reject"
			} else {
				cfg.Rules[i].OnError = "skip"
			}
		}
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
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `go test ./internal/policy/`
Expected: FAIL (undefined `policy.New`, `policy.Engine`, ...).

- [ ] **Step 3: Implement the engine**

Create `internal/policy/engine.go`:

```go
package policy

import (
	"fmt"
	"log/slog"
	"reflect"

	"github.com/google/cel-go/cel"
	"github.com/google/cel-go/common/types"

	"github.com/abinnovision/frp-server-plugin-cel/internal/config"
)

type Action string

const (
	ActionAllow   Action = "allow"
	ActionReject  Action = "reject"
	ActionRewrite Action = "rewrite"
)

// Decision is the outcome of evaluating one request. Rule holds the
// matched rule's name, or "default" when defaultAction applied.
type Decision struct {
	Action  Action
	Reason  string
	Content map[string]any
	Rule    string
}

type compiledRule struct {
	cfg     config.Rule
	ops     map[string]bool
	when    cel.Program
	content cel.Program // non-nil only for rewrite rules
}

// Engine evaluates requests against the configured rule chain. Compiled
// cel.Programs are safe for concurrent use, so one Engine serves all
// requests.
type Engine struct {
	rules         []compiledRule
	defaultAction Action
	defaultReason string
	logger        *slog.Logger
}

// New compiles every rule's CEL expressions and fails fast on the first
// error, naming the offending rule.
func New(cfg *config.Config, logger *slog.Logger) (*Engine, error) {
	env, err := NewEnv()
	if err != nil {
		return nil, fmt.Errorf("create CEL environment: %w", err)
	}
	e := &Engine{
		defaultAction: Action(cfg.DefaultAction),
		defaultReason: cfg.DefaultRejectReason,
		logger:        logger,
	}
	for _, r := range cfg.Rules {
		cr := compiledRule{cfg: r, ops: make(map[string]bool, len(r.Ops))}
		for _, op := range r.Ops {
			cr.ops[op] = true
		}
		cr.when, err = compile(env, r.Name, "when", r.When, types.BoolKind)
		if err != nil {
			return nil, err
		}
		if r.Action == "rewrite" {
			cr.content, err = compile(env, r.Name, "content", r.Content, types.MapKind)
			if err != nil {
				return nil, err
			}
		}
		e.rules = append(e.rules, cr)
	}
	return e, nil
}

// compile compiles expr and enforces the expected output kind where the
// checker can prove it. Dyn passes (content is dyn, so most expressions
// infer as dyn); kind-based matching accepts any map type for rewrites —
// a bare literal like {"a": "b"} checks as map(string, string), which an
// exact-type comparison against map(dyn, dyn) would wrongly reject.
func compile(env *cel.Env, rule, field, expr string, want types.Kind) (cel.Program, error) {
	ast, iss := env.Compile(expr)
	if iss.Err() != nil {
		return nil, fmt.Errorf("rule %q: compile %s: %w", rule, field, iss.Err())
	}
	out := ast.OutputType()
	if out.Kind() != types.DynKind && out.Kind() != want {
		return nil, fmt.Errorf("rule %q: %s must evaluate to %v, got %s", rule, field, want, out)
	}
	prg, err := env.Program(ast)
	if err != nil {
		return nil, fmt.Errorf("rule %q: program %s: %w", rule, field, err)
	}
	return prg, nil
}

// Evaluate walks the rules that apply to op in config order; the first
// rule whose `when` is true determines the decision. No match falls
// through to the default action.
func (e *Engine) Evaluate(op string, content map[string]any) Decision {
	if content == nil {
		content = map[string]any{}
	}
	vars := map[string]any{"op": op, "content": content}
	for _, r := range e.rules {
		if !r.ops[op] {
			continue
		}
		matched, err := evalBool(r.when, vars)
		if err != nil {
			if d, halt := e.handleEvalError(r, op, err); halt {
				return d
			}
			continue
		}
		if !matched {
			continue
		}
		switch Action(r.cfg.Action) {
		case ActionAllow:
			return Decision{Action: ActionAllow, Rule: r.cfg.Name}
		case ActionReject:
			return Decision{Action: ActionReject, Reason: r.cfg.Reason, Rule: r.cfg.Name}
		case ActionRewrite:
			overlay, err := evalMap(r.content, vars)
			if err != nil {
				if d, halt := e.handleEvalError(r, op, err); halt {
					return d
				}
				continue
			}
			merged := make(map[string]any, len(content)+len(overlay))
			for k, v := range content {
				merged[k] = v
			}
			for k, v := range overlay {
				merged[k] = v
			}
			return Decision{Action: ActionRewrite, Content: merged, Rule: r.cfg.Name}
		}
	}
	return Decision{
		Action: e.defaultAction,
		Reason: e.defaultRejectReason(),
		Rule:   "default",
	}
}

func (e *Engine) defaultRejectReason() string {
	if e.defaultAction == ActionReject {
		return e.defaultReason
	}
	return ""
}

// handleEvalError applies the rule's onError policy. Reject rules default
// to onError=reject (fail closed): an error in a security rule must not
// become an allow.
func (e *Engine) handleEvalError(r compiledRule, op string, err error) (Decision, bool) {
	e.logger.Warn("rule evaluation error",
		"rule", r.cfg.Name, "op", op, "onError", r.cfg.OnError, "error", err.Error())
	if r.cfg.OnError == "reject" {
		reason := r.cfg.Reason
		if reason == "" {
			reason = "policy evaluation error"
		}
		return Decision{Action: ActionReject, Reason: reason, Rule: r.cfg.Name}, true
	}
	return Decision{}, false
}

func evalBool(prg cel.Program, vars map[string]any) (bool, error) {
	out, _, err := prg.Eval(vars)
	if err != nil {
		return false, err
	}
	b, ok := out.Value().(bool)
	if !ok {
		return false, fmt.Errorf("expression returned %s, want bool", out.Type().TypeName())
	}
	return b, nil
}

func evalMap(prg cel.Program, vars map[string]any) (map[string]any, error) {
	out, _, err := prg.Eval(vars)
	if err != nil {
		return nil, err
	}
	native, err := out.ConvertToNative(reflect.TypeOf(map[string]any{}))
	if err != nil {
		return nil, fmt.Errorf("rewrite expression returned %s, want map: %w", out.Type().TypeName(), err)
	}
	m, ok := native.(map[string]any)
	if !ok {
		return nil, fmt.Errorf("rewrite expression returned %T, want map", native)
	}
	return m, nil
}
```

Note: `types.Kind`/`out.Kind()` come from `github.com/google/cel-go/common/types`; in current cel-go, `*cel.Type` is an alias of `*types.Type` and exposes `Kind()`. If the installed version differs, adapt the kind check, keeping the semantics (dyn passes; bool for `when`, any map for `content`).

- [ ] **Step 4: Run tests to verify they pass**

Run: `go test ./internal/policy/ -v`
Expected: PASS, all tests. If `slog.DiscardHandler` is unavailable (needs Go ≥1.24), use `slog.NewTextHandler(io.Discard, nil)`.

- [ ] **Step 5: Commit**

```bash
git add internal/policy/
git commit -m "feat: first-match-wins policy engine with fail-closed onError"
```

---

### Task 4: HTTP server

**Files:**
- Create: `internal/server/server.go`
- Test: `internal/server/server_test.go`

**Interfaces:**
- Consumes: `policy.Engine.Evaluate(op, content) policy.Decision` (Task 3).
- Produces: `server.Handler(engine *policy.Engine, logger *slog.Logger) http.Handler` — the frp plugin endpoint handler (op from query string, JSON body, frp envelope out). Task 5 mounts it on a mux together with `/healthz`.

- [ ] **Step 1: Write the failing tests**

Create `internal/server/server_test.go`:

```go
package server_test

import (
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/abinnovision/frp-server-plugin-cel/internal/config"
	"github.com/abinnovision/frp-server-plugin-cel/internal/policy"
	"github.com/abinnovision/frp-server-plugin-cel/internal/server"
)

func testHandler(t *testing.T) http.Handler {
	t.Helper()
	logger := slog.New(slog.DiscardHandler)
	engine, err := policy.New(&config.Config{
		DefaultAction:       "allow",
		DefaultRejectReason: "rejected by default policy",
		Rules: []config.Rule{
			{
				Name: "domains", Ops: []string{"NewProxy"},
				When:   `has(content.custom_domains) && !content.custom_domains.all(d, d.endsWith(".tunnels.example.com"))`,
				Action: "reject", Reason: "custom_domains must be under *.tunnels.example.com",
				OnError: "reject",
			},
			{
				Name: "ci-bw", Ops: []string{"NewProxy"},
				When:   `content.user.user == 'ci-bot'`,
				Action: "rewrite", Content: `{"bandwidth_limit": "1MB"}`, OnError: "skip",
			},
		},
	}, logger)
	if err != nil {
		t.Fatal(err)
	}
	return server.Handler(engine, logger)
}

func post(t *testing.T, h http.Handler, url, body string) *httptest.ResponseRecorder {
	t.Helper()
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, url, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	h.ServeHTTP(rec, req)
	return rec
}

func TestAllowEnvelope(t *testing.T) {
	rec := post(t, testHandler(t), "/handler?op=Ping&version=0.1.0",
		`{"version":"0.1.0","op":"Ping","content":{"user":{"user":"andre"}}}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d", rec.Code)
	}
	var m map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &m); err != nil {
		t.Fatal(err)
	}
	if m["reject"] != false || m["unchange"] != true {
		t.Errorf("allow envelope wrong: %s", rec.Body.String())
	}
	if _, hasContent := m["content"]; hasContent {
		t.Errorf("allow envelope must omit content: %s", rec.Body.String())
	}
}

func TestRejectEnvelope(t *testing.T) {
	rec := post(t, testHandler(t), "/handler?op=NewProxy",
		`{"content":{"user":{"user":"andre"},"proxy_name":"web","custom_domains":["evil.example.com"]}}`)
	var m map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &m); err != nil {
		t.Fatal(err)
	}
	if m["reject"] != true || m["reject_reason"] != "custom_domains must be under *.tunnels.example.com" {
		t.Errorf("reject envelope wrong: %s", rec.Body.String())
	}
}

func TestRewriteEnvelopePreservesFields(t *testing.T) {
	rec := post(t, testHandler(t), "/handler?op=NewProxy",
		`{"content":{"user":{"user":"ci-bot"},"proxy_name":"web","custom_domains":["a.tunnels.example.com"]}}`)
	var m struct {
		Reject   bool           `json:"reject"`
		Unchange bool           `json:"unchange"`
		Content  map[string]any `json:"content"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &m); err != nil {
		t.Fatal(err)
	}
	if m.Reject || m.Unchange {
		t.Errorf("rewrite envelope wrong: %s", rec.Body.String())
	}
	if m.Content["bandwidth_limit"] != "1MB" || m.Content["proxy_name"] != "web" {
		t.Errorf("rewrite content wrong: %#v", m.Content)
	}
}

func TestMissingOpIs400(t *testing.T) {
	if rec := post(t, testHandler(t), "/handler", `{}`); rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", rec.Code)
	}
}

func TestMalformedBodyIs400(t *testing.T) {
	if rec := post(t, testHandler(t), "/handler?op=Ping", `{not json`); rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", rec.Code)
	}
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `go test ./internal/server/`
Expected: FAIL (undefined `server.Handler`).

- [ ] **Step 3: Implement the handler**

Create `internal/server/server.go`:

```go
// Package server exposes the policy engine over frp's server plugin HTTP
// protocol.
package server

import (
	"encoding/json"
	"log/slog"
	"net/http"

	"github.com/abinnovision/frp-server-plugin-cel/internal/policy"
)

// request mirrors frp's plugin request envelope {version, op, content}.
// op is taken from the query string (frps sends it there); the body's
// version and op fields are ignored.
type request struct {
	Content map[string]any `json:"content"`
}

// response mirrors frp's plugin response envelope. On allow, unchange must
// be true and content omitted — unchange:false with empty content would
// zero the proxy configuration in frps.
type response struct {
	Reject       bool           `json:"reject"`
	RejectReason string         `json:"reject_reason,omitempty"`
	Unchange     bool           `json:"unchange"`
	Content      map[string]any `json:"content,omitempty"`
}

// Handler returns the frp plugin endpoint handler. Mount it for POST on
// the configured path.
func Handler(engine *policy.Engine, logger *slog.Logger) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		op := r.URL.Query().Get("op")
		if op == "" {
			http.Error(w, "missing op query parameter", http.StatusBadRequest)
			return
		}
		var req request
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "malformed request body", http.StatusBadRequest)
			return
		}

		decision := engine.Evaluate(op, req.Content)
		logDecision(logger, op, decision)

		resp := response{}
		switch decision.Action {
		case policy.ActionAllow:
			resp.Unchange = true
		case policy.ActionReject:
			resp.Reject = true
			resp.RejectReason = decision.Reason
		case policy.ActionRewrite:
			resp.Content = decision.Content
		}
		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(resp); err != nil {
			logger.Error("write response", "error", err.Error())
		}
	})
}

func logDecision(logger *slog.Logger, op string, d policy.Decision) {
	attrs := []any{"op", op, "rule", d.Rule, "action", string(d.Action)}
	if d.Action == policy.ActionReject {
		attrs = append(attrs, "reason", d.Reason)
	}
	logger.Info("decision", attrs...)
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `go test ./internal/server/ -v`
Expected: PASS, all tests.

- [ ] **Step 5: Run the full suite and commit**

Run: `go test ./...`
Expected: PASS across all packages.

```bash
git add internal/server/
git commit -m "feat: frp plugin HTTP handler with exact response envelopes"
```

---

### Task 5: main.go wiring and smoke test

**Files:**
- Create: `cmd/frp-cel-plugin/main.go`
- Create: `config.example.yaml`

**Interfaces:**
- Consumes: `config.Load`, `(*Config).Lint` (Task 1), `policy.New` (Task 3), `server.Handler` (Task 4).
- Produces: the `frp-cel-plugin` binary. `var version = "dev"` in package main (set by GoReleaser via `-X main.version={{.Version}}`, Task 6). Flag: `-config <path>` (default `config.yaml`).

- [ ] **Step 1: Write main.go**

Create `cmd/frp-cel-plugin/main.go`:

```go
// Command frp-cel-plugin is an frp server plugin (HTTP) that decides
// allow/reject/rewrite per lifecycle op via configured CEL rules.
package main

import (
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"time"

	"github.com/abinnovision/frp-server-plugin-cel/internal/config"
	"github.com/abinnovision/frp-server-plugin-cel/internal/policy"
	"github.com/abinnovision/frp-server-plugin-cel/internal/server"
)

// version is injected by GoReleaser via -ldflags "-X main.version=...".
var version = "dev"

func main() {
	configPath := flag.String("config", "config.yaml", "path to the YAML config file")
	showVersion := flag.Bool("version", false, "print version and exit")
	flag.Parse()

	if *showVersion {
		fmt.Println(version)
		return
	}

	logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))

	cfg, err := config.Load(*configPath)
	if err != nil {
		logger.Error("load config", "error", err.Error())
		os.Exit(1)
	}
	for _, warning := range cfg.Lint() {
		logger.Warn("config lint", "warning", warning)
	}

	engine, err := policy.New(cfg, logger)
	if err != nil {
		logger.Error("compile policy", "error", err.Error())
		os.Exit(1)
	}

	mux := http.NewServeMux()
	mux.Handle("POST "+cfg.Path, server.Handler(engine, logger))
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})

	// frps's plugin client has no timeout; bounding our side prevents a
	// stuck connection from pinning resources.
	srv := &http.Server{
		Addr:              cfg.Bind,
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      10 * time.Second,
	}
	logger.Info("listening", "bind", cfg.Bind, "path", cfg.Path, "version", version, "rules", len(cfg.Rules))
	if err := srv.ListenAndServe(); err != nil {
		logger.Error("server", "error", err.Error())
		os.Exit(1)
	}
}
```

Create `config.example.yaml`:

```yaml
# yaml-language-server: $schema=./config.schema.json
bind: ":9001"
path: /handler
defaultAction: allow
rules:
  - name: restrict-custom-domains
    ops: [NewProxy]
    when: |
      has(content.custom_domains) &&
      !content.custom_domains.all(d, d.endsWith(".tunnels.example.com"))
    action: reject
    reason: "custom_domains must be under *.tunnels.example.com"
  - name: force-ci-bandwidth-limit
    ops: [NewProxy]
    when: "content.user.user == 'ci-bot'"
    action: rewrite
    content: |
      content.with({"bandwidth_limit": "1MB"})
```

- [ ] **Step 2: Build and smoke test end-to-end**

```bash
go build -o /tmp/frp-cel-plugin ./cmd/frp-cel-plugin
/tmp/frp-cel-plugin -config config.example.yaml &
sleep 1
curl -s http://localhost:9001/healthz
curl -s -X POST 'http://localhost:9001/handler?op=NewProxy&version=0.1.0' \
  -d '{"version":"0.1.0","op":"NewProxy","content":{"user":{"user":"andre"},"proxy_name":"web","proxy_type":"http","custom_domains":["evil.example.com"]}}'
curl -s -X POST 'http://localhost:9001/handler?op=NewProxy&version=0.1.0' \
  -d '{"version":"0.1.0","op":"NewProxy","content":{"user":{"user":"andre"},"proxy_name":"web","proxy_type":"http","custom_domains":["ok.tunnels.example.com"]}}'
kill %1
```

Expected output, in order: `ok`, then `{"reject":true,"reject_reason":"custom_domains must be under *.tunnels.example.com","unchange":false}`, then `{"reject":false,"unchange":true}`.

- [ ] **Step 3: Run vet and the full suite**

Run: `go vet ./... && go test ./...`
Expected: no vet findings, all tests PASS.

- [ ] **Step 4: Commit**

```bash
git add cmd/ config.example.yaml
git commit -m "feat: main entrypoint with healthz, timeouts, and example config"
```

---

### Task 6: Release automation (Dockerfile, GoReleaser, GitHub Actions)

**Files:**
- Create: `Dockerfile`
- Create: `.goreleaser.yaml`
- Create: `.github/workflows/release.yaml`
- Create: `.gitignore`

**Interfaces:**
- Consumes: `cmd/frp-cel-plugin` build target, `var version` (Task 5).
- Produces: on push to `main` with release-worthy conventional commits — svu computes the next semver, the workflow tags, then publishes a GitHub Release with binaries + checksums and multi-arch images `ghcr.io/abinnovision/frp-server-plugin-cel:{version}` / `:latest` (manifests over `-amd64`/`-arm64`). No manual tagging.

- [ ] **Step 1: Write the Dockerfile and .gitignore**

Create `Dockerfile` (GoReleaser copies the prebuilt binary into the build context; there is no Go toolchain stage):

```dockerfile
FROM gcr.io/distroless/static-debian12:nonroot
COPY frp-cel-plugin /usr/local/bin/frp-cel-plugin
USER nonroot:nonroot
ENTRYPOINT ["/usr/local/bin/frp-cel-plugin"]
CMD ["-config", "/etc/frp-cel-plugin/config.yaml"]
```

Create `.gitignore`:

```
dist/
```

- [ ] **Step 2: Write .goreleaser.yaml**

Create `.goreleaser.yaml`:

```yaml
version: 2

project_name: frp-cel-plugin

builds:
  - id: frp-cel-plugin
    main: ./cmd/frp-cel-plugin
    binary: frp-cel-plugin
    env:
      - CGO_ENABLED=0
    flags:
      - -trimpath
    ldflags:
      - -s -w -X main.version={{.Version}}
    goos:
      - linux
      - darwin
    goarch:
      - amd64
      - arm64
    ignore:
      - goos: darwin
        goarch: amd64

dockers:
  - id: linux-amd64
    use: buildx
    goos: linux
    goarch: amd64
    image_templates:
      - ghcr.io/abinnovision/frp-server-plugin-cel:{{ .Version }}-amd64
    build_flag_templates:
      - --platform=linux/amd64
      - --label=org.opencontainers.image.title={{ .ProjectName }}
      - --label=org.opencontainers.image.source=https://github.com/abinnovision/frp-server-plugin-cel
      - --label=org.opencontainers.image.version={{ .Version }}
      - --label=org.opencontainers.image.revision={{ .FullCommit }}
  - id: linux-arm64
    use: buildx
    goos: linux
    goarch: arm64
    image_templates:
      - ghcr.io/abinnovision/frp-server-plugin-cel:{{ .Version }}-arm64
    build_flag_templates:
      - --platform=linux/arm64
      - --label=org.opencontainers.image.title={{ .ProjectName }}
      - --label=org.opencontainers.image.source=https://github.com/abinnovision/frp-server-plugin-cel
      - --label=org.opencontainers.image.version={{ .Version }}
      - --label=org.opencontainers.image.revision={{ .FullCommit }}

docker_manifests:
  - name_template: ghcr.io/abinnovision/frp-server-plugin-cel:{{ .Version }}
    image_templates:
      - ghcr.io/abinnovision/frp-server-plugin-cel:{{ .Version }}-amd64
      - ghcr.io/abinnovision/frp-server-plugin-cel:{{ .Version }}-arm64
  - name_template: ghcr.io/abinnovision/frp-server-plugin-cel:latest
    image_templates:
      - ghcr.io/abinnovision/frp-server-plugin-cel:{{ .Version }}-amd64
      - ghcr.io/abinnovision/frp-server-plugin-cel:{{ .Version }}-arm64

archives:
  - formats: [tar.gz]

checksum:
  name_template: checksums.txt

changelog:
  sort: asc
  groups:
    - title: Features
      regexp: '^feat'
      order: 0
    - title: Fixes
      regexp: '^fix'
      order: 1
    - title: Other
      order: 999
```

- [ ] **Step 3: Write the release workflow**

Versioning is automated from conventional commits with svu: on every push
to `main`, compute the next version; when it differs from the current one,
tag and release in the SAME workflow run. This is mandatory, not a
convenience: tags pushed with `GITHUB_TOKEN` do not trigger other
workflows (GitHub's recursion guard), so a separate tagger workflow would
never start the release.

Create `.github/workflows/release.yaml`:

```yaml
name: release

on:
  push:
    branches:
      - main

permissions:
  contents: write
  packages: write

jobs:
  release:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0 # svu and the GoReleaser changelog need full history + tags
      - uses: actions/setup-go@v5
        with:
          go-version-file: go.mod
      - name: Compute next version
        id: svu
        run: |
          go install github.com/caarlos0/svu/v3@latest
          current="$(svu current 2>/dev/null || echo v0.0.0)"
          next="$(svu next)"
          echo "current=${current} next=${next}"
          echo "next=${next}" >> "$GITHUB_OUTPUT"
          if [ "${next}" = "${current}" ]; then
            echo "release=false" >> "$GITHUB_OUTPUT"
          else
            echo "release=true" >> "$GITHUB_OUTPUT"
          fi
      - name: Create tag
        if: steps.svu.outputs.release == 'true'
        run: |
          git config user.name "github-actions[bot]"
          git config user.email "github-actions[bot]@users.noreply.github.com"
          git tag -a "${{ steps.svu.outputs.next }}" -m "${{ steps.svu.outputs.next }}"
          git push origin "refs/tags/${{ steps.svu.outputs.next }}"
      # QEMU is not strictly required for a COPY-only Dockerfile, but is
      # harmless belt-and-suspenders for future RUN steps.
      - uses: docker/setup-qemu-action@v3
        if: steps.svu.outputs.release == 'true'
      - uses: docker/setup-buildx-action@v3
        if: steps.svu.outputs.release == 'true'
      - uses: docker/login-action@v3
        if: steps.svu.outputs.release == 'true'
        with:
          registry: ghcr.io
          username: ${{ github.actor }}
          password: ${{ secrets.GITHUB_TOKEN }}
      - uses: goreleaser/goreleaser-action@v6
        if: steps.svu.outputs.release == 'true'
        with:
          version: "~> v2"
          args: release --clean
        env:
          GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
```

Notes for the implementer:
- svu derives the bump from conventional commits since the last tag:
  `fix:` → patch, `feat:` → minor, `feat!:`/`BREAKING CHANGE:` → major;
  other types (`docs:`, `build:`, `chore:`) produce no new version, so the
  run ends after the svu step. On a repo with no tags yet, `svu next`
  yields `v0.1.0`.
- If `svu current` errors on a tagless repo in the installed version,
  the `|| echo v0.0.0` fallback covers it.
- GoReleaser runs on the tagged HEAD created two steps earlier in the same
  checkout, so it sees a clean worktree and the correct `{{ .Version }}`.

- [ ] **Step 4: Validate the GoReleaser config**

Run: `command -v goreleaser >/dev/null && goreleaser check || echo "goreleaser not installed - skipping local check"`
Expected: `1 configuration file(s) validated` (or the skip message; the config is then validated by the first tag push). If `goreleaser check` reports deprecated/renamed fields (e.g. `archives.formats` on older v2 minors), fix per its message.

Optionally, if Docker and goreleaser are both available locally:
Run: `goreleaser release --snapshot --clean --skip=docker` (background this; it builds all binaries)
Expected: `dist/` populated with binaries and archives.

- [ ] **Step 5: Commit**

```bash
git add Dockerfile .goreleaser.yaml .github/ .gitignore
git commit -m "build: GoReleaser multi-arch release pipeline to GHCR"
```

---

### Task 7: Examples and README

**Files:**
- Create: `examples/frps-httpplugins.toml`
- Create: `examples/kubernetes.yaml`
- Create: `README.md`

**Interfaces:**
- Consumes: binary flags and config format from Tasks 1/5, image name from Task 6.
- Produces: user-facing documentation and deployable examples. No code.

- [ ] **Step 1: Write the frps.toml snippet**

Create `examples/frps-httpplugins.toml`:

```toml
# Add to frps.toml — frps calls the plugin synchronously on these ops.
[[httpPlugins]]
name = "frp-cel-plugin"
addr = "127.0.0.1:9001"
path = "/handler"
ops = ["Login", "NewProxy"]
```

- [ ] **Step 2: Write the Kubernetes example**

Create `examples/kubernetes.yaml` (plugin as a sidecar next to frps — the frp plugin protocol is unauthenticated plaintext HTTP, so keep it on localhost or behind a NetworkPolicy):

```yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: frp-cel-plugin-config
data:
  config.yaml: |
    bind: ":9001"
    path: /handler
    defaultAction: allow
    rules:
      - name: restrict-custom-domains
        ops: [NewProxy]
        when: |
          has(content.custom_domains) &&
          !content.custom_domains.all(d, d.endsWith(".tunnels.example.com"))
        action: reject
        reason: "custom_domains must be under *.tunnels.example.com"
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: frps
spec:
  replicas: 1
  selector:
    matchLabels:
      app: frps
  template:
    metadata:
      labels:
        app: frps
    spec:
      containers:
        - name: frps
          image: fatedier/frps:v0.61.1
          args: ["-c", "/etc/frp/frps.toml"]
          # frps.toml must contain the [[httpPlugins]] block from
          # examples/frps-httpplugins.toml, pointing at 127.0.0.1:9001.
          volumeMounts:
            - name: frps-config
              mountPath: /etc/frp
        - name: frp-cel-plugin
          image: ghcr.io/abinnovision/frp-server-plugin-cel:latest
          args: ["-config", "/etc/frp-cel-plugin/config.yaml"]
          ports:
            - containerPort: 9001
          readinessProbe:
            httpGet:
              path: /healthz
              port: 9001
          livenessProbe:
            httpGet:
              path: /healthz
              port: 9001
          volumeMounts:
            - name: plugin-config
              mountPath: /etc/frp-cel-plugin
      volumes:
        - name: plugin-config
          configMap:
            name: frp-cel-plugin-config
        - name: frps-config
          configMap:
            name: frps-config # provide separately; not part of this example
```

- [ ] **Step 3: Write the README**

Create `README.md` covering, in this order (write real prose, not placeholders):

1. **What it is** — one paragraph: frp server plugin (`[[httpPlugins]]`) that decides allow/reject/rewrite per lifecycle op via CEL rules; link to frp's server plugin docs (`https://github.com/fatedier/frp/blob/dev/doc/server_plugin.md`).
2. **Quick start** — the `config.example.yaml` content, the frps.toml block from `examples/frps-httpplugins.toml`, and `docker run -v $(pwd)/config.yaml:/etc/frp-cel-plugin/config.yaml ghcr.io/abinnovision/frp-server-plugin-cel:latest`.
3. **Configuration reference** — the field table from the design spec (`bind`, `path`, `defaultAction`, `defaultRejectReason`, and all `rules[]` fields including `onError` with its per-action defaults). Mention the JSON Schema and the `# yaml-language-server: $schema=` modeline for editor support.
4. **CEL reference** — variables `op` and `content`; note `endsWith`/`startsWith`/`contains`/`matches` are built-ins, strings extension adds `split`/`join`/`replace`/`format`; document `content.with({...})` and that rewrite results are shallow-merged onto the original content server-side, so partial maps are safe.
5. **Semantics and caveats** — first-match-wins ordering; eval errors fail closed on reject rules (`onError`); `CloseProxy` responses are discarded by frps (rules on it are log-only); the plugin channel is unauthenticated plaintext HTTP — run as a localhost sidecar or restrict with NetworkPolicy.
6. **Example policies** — the domain restriction and CI bandwidth rewrite from `config.example.yaml`, plus one Login example: reject logins without a meta key (`when: "!has(content.metas.team)"`, ops `[Login]`).
7. **Releases** — versions are computed automatically from conventional commits (svu: `fix:` → patch, `feat:` → minor, breaking → major); pushes to `main` tag and publish multi-arch images to GHCR and binaries to GitHub Releases via GoReleaser. Commit style therefore matters: use semantic commit messages.

- [ ] **Step 4: Final verification**

Run: `go vet ./... && go test ./...`
Expected: all PASS.

- [ ] **Step 5: Commit**

```bash
git add examples/ README.md
git commit -m "docs: README, frps.toml snippet, and Kubernetes sidecar example"
```
