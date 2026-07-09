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
