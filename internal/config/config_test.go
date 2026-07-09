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
