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
