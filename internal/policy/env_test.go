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
