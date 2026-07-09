package server_test

import (
	"bytes"
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
	return testHandlerWithLogger(t, slog.New(slog.DiscardHandler))
}

func testHandlerWithLogger(t *testing.T, logger *slog.Logger) http.Handler {
	t.Helper()
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

func TestOversizedBodyIs400(t *testing.T) {
	huge := strings.Repeat("a", 1<<20+1)
	body := `{"content":{"user":{"user":"` + huge + `"}}}`
	if rec := post(t, testHandler(t), "/handler?op=Ping", body); rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", rec.Code)
	}
}

// lastLogLine decodes the last JSON log line written to buf.
func lastLogLine(t *testing.T, buf *bytes.Buffer) map[string]any {
	t.Helper()
	lines := strings.Split(strings.TrimSpace(buf.String()), "\n")
	if len(lines) == 0 || lines[0] == "" {
		t.Fatal("no log output")
	}
	var m map[string]any
	if err := json.Unmarshal([]byte(lines[len(lines)-1]), &m); err != nil {
		t.Fatalf("log line not JSON: %v: %s", err, lines[len(lines)-1])
	}
	return m
}

func TestRejectDecisionIsLogged(t *testing.T) {
	var buf bytes.Buffer
	h := testHandlerWithLogger(t, slog.New(slog.NewJSONHandler(&buf, nil)))
	post(t, h, "/handler?op=NewProxy",
		`{"content":{"user":{"user":"andre"},"proxy_name":"web","custom_domains":["evil.example.com"]}}`)
	m := lastLogLine(t, &buf)
	if m["msg"] != "decision" {
		t.Fatalf("msg = %v, want decision (log: %s)", m["msg"], buf.String())
	}
	if m["op"] != "NewProxy" || m["rule"] != "domains" || m["action"] != "reject" ||
		m["reason"] != "custom_domains must be under *.tunnels.example.com" {
		t.Errorf("decision log fields wrong: %s", buf.String())
	}
}

func TestBadRequestsAreLogged(t *testing.T) {
	t.Run("missing op", func(t *testing.T) {
		var buf bytes.Buffer
		h := testHandlerWithLogger(t, slog.New(slog.NewJSONHandler(&buf, nil)))
		post(t, h, "/handler", `{}`)
		m := lastLogLine(t, &buf)
		if m["level"] != "WARN" || m["msg"] != "bad request" || m["error"] != "missing op query parameter" {
			t.Errorf("missing-op warn log wrong: %s", buf.String())
		}
	})
	t.Run("malformed body", func(t *testing.T) {
		var buf bytes.Buffer
		h := testHandlerWithLogger(t, slog.New(slog.NewJSONHandler(&buf, nil)))
		post(t, h, "/handler?op=Ping", `{not json`)
		m := lastLogLine(t, &buf)
		if m["level"] != "WARN" || m["msg"] != "bad request" || m["op"] != "Ping" || m["error"] == "" {
			t.Errorf("malformed-body warn log wrong: %s", buf.String())
		}
	})
}
