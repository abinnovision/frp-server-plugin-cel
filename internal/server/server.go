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
			logger.Warn("bad request", "error", "missing op query parameter")
			http.Error(w, "missing op query parameter", http.StatusBadRequest)
			return
		}
		r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
		var req request
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			logger.Warn("bad request", "op", op, "error", err.Error())
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
