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

	defaultAction := cfg.DefaultAction
	if defaultAction == "" {
		defaultAction = "allow"
	}
	if defaultAction != "allow" && defaultAction != "reject" {
		return nil, fmt.Errorf("defaultAction: must be allow or reject, got %q", defaultAction)
	}

	e := &Engine{
		defaultAction: Action(defaultAction),
		defaultReason: cfg.DefaultRejectReason,
		logger:        logger,
	}
	for _, r := range cfg.Rules {
		if r.Action != "allow" && r.Action != "reject" && r.Action != "rewrite" {
			return nil, fmt.Errorf("rule %q: action must be allow, reject, or rewrite, got %q", r.Name, r.Action)
		}

		cr := compiledRule{cfg: r, ops: make(map[string]bool, len(r.Ops))}
		if cr.cfg.OnError == "" {
			if cr.cfg.Action == "reject" {
				cr.cfg.OnError = "reject"
			} else {
				cr.cfg.OnError = "skip"
			}
		}
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
