# Design: frp-server-plugin-cel

Date: 2026-07-09
Status: Approved

## Purpose

A standalone Go service implementing frp's server plugin HTTP protocol
(`[[httpPlugins]]` in frps.toml). frps calls it synchronously on lifecycle
operations (`Login`, `NewProxy`, `Ping`, `NewWorkConn`, `NewUserConn`,
`CloseProxy`); the service evaluates user-configured CEL rules and responds
with one of three outcomes per the frp spec:

- **allow** — `{"reject": false, "unchange": true}`
- **reject** — `{"reject": true, "reject_reason": "<reason>"}`
- **rewrite** — `{"reject": false, "unchange": false, "content": {...}}`

First concrete use case: reject `NewProxy` requests whose `custom_domains`
fall outside `*.tunnels.example.com`.

**Per-op capabilities:** reject and rewrite take effect on `Login`,
`NewProxy`, `Ping`, `NewWorkConn`, and `NewUserConn`. For `CloseProxy`,
frps discards the plugin response entirely (verified in
`pkg/plugin/server/manager.go`) — rules on it are observability-only. The
config loader emits a warning when a `reject`/`rewrite` rule targets
`CloseProxy`. Unknown/future op names in `ops` are accepted without
validation, by design.

## Requirements

- Generic over ops: one handler serves every op frp sends, including future
  ones. Request content is treated as dynamic JSON; no typed structs per op.
- Policy expressed as CEL. Rules are an ordered list; first match wins;
  configurable `defaultAction` (default: `allow`).
- Rewrite content is produced by a CEL expression evaluating to a map.
- Kubernetes-first: config is a single YAML file (mounted as ConfigMap).
- A JSON Schema for the config file, used for editor tooling and validated
  at load time.
- `GET /healthz` for probes.
- Deliverables include container images and example Kubernetes manifests.
- Releases are automated with GoReleaser: multi-arch container images and
  binary GitHub Releases on tag push.
- Out of scope for v1: config hot-reload, Prometheus metrics, mTLS.

## Architecture

Single binary (`cmd/frp-cel-plugin`), minimal dependencies:
`github.com/google/cel-go`, `gopkg.in/yaml.v3`, and a lightweight JSON
Schema validator (e.g. `github.com/santhosh-tekuri/jsonschema/v6`).

Packages:

- `internal/config` — loads the YAML file, validates it against the embedded
  JSON Schema (`go:embed config.schema.json`), then compiles every CEL
  expression. Any structural or CEL compile error aborts startup with a
  clear message naming the rule.
- `internal/policy` — the engine. Input: op name + decoded request content
  (`map[string]any`). Walks the rules whose `ops` list contains the op, in
  file order; the first rule whose `when` evaluates to `true` determines the
  decision. No match → `defaultAction`. Output: a `Decision` value
  (Allow | Reject{Reason} | Rewrite{Content map[string]any}).
- `internal/server` — `net/http` handler for `POST <path>` (default
  `/handler`). Reads `op` from the query string (the body's `version` field
  is ignored), unmarshals the JSON body, extracts its `content` field, calls
  the policy engine, writes the frp response envelope. Allow responses send
  `{"reject": false, "unchange": true}` and must omit `content` — sending
  `unchange: false` with no content would zero the proxy config in frps.
  Also serves `GET /healthz` (200 "ok"). The `http.Server` sets
  `ReadHeaderTimeout`, `ReadTimeout`, and `WriteTimeout` (frps's plugin
  client has no timeout, so a hung plugin would block frps indefinitely).
  Plaintext HTTP only in v1: the frp plugin protocol carries no
  authentication, so the deployment assumption is a localhost sidecar or a
  network-policy-restricted in-cluster Service.

## CEL environment

Each evaluation exposes two variables:

- `op` — string, the frp operation name.
- `content` — dynamic map, the request body's `content` object exactly as
  frp sent it (e.g. `content.custom_domains`, `content.user.metas`).

Enabled: standard CEL macros (`all`, `exists`, `has`, ...) — note that
`endsWith`, `startsWith`, `contains`, and `matches` are CEL built-ins — plus
the strings extension library for extras like `split`, `join`, `replace`,
and `format`. Programs are compiled once
at startup and shared; `cel.Program` is safe for concurrent use.

One custom function is registered: `with(map, map) -> map`, a shallow merge
returning the receiver with the argument's keys overlaid (e.g.
`content.with({"bandwidth_limit": "1MB"})`). Implementing this on a `dyn`
receiver (overload resolution + adapting the result back to a `ref.Val`) is
a real implementation task and gets a dedicated unit test.

**Rewrite safety:** frps unmarshals the response `content` into a fresh
zero-valued struct, so any field omitted by the plugin is wiped, not
preserved. To make partial rewrites safe by construction, the engine always
shallow-merges the rewrite expression's result onto the original decoded
content before responding — a bare `{"bandwidth_limit": "1MB"}` therefore
behaves like `content.with(...)` and cannot zero `proxy_name` or
`custom_domains`. A test asserts field preservation.

Rule `when` expressions must be of type bool (checked at compile time where
possible). Rewrite `content` expressions must evaluate to a map; the result
is JSON-serialized as the response `content`.

## Configuration

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
      // CEL expression producing the full modified content map
      content.with({"bandwidth_limit": "1MB"})
```

Fields:

| Field | Type | Notes |
|---|---|---|
| `bind` | string | Listen address; default `":9001"`. |
| `path` | string | Handler path; default `/handler`. |
| `defaultAction` | `allow` \| `reject` | Applied when no rule matches; default `allow`. Default rejects use reason "rejected by default policy" (overridable via `defaultRejectReason`). |
| `rules[].name` | string | Required, unique; used in logs and errors. |
| `rules[].ops` | string[] | Required; frp op names this rule applies to. |
| `rules[].when` | string (CEL → bool) | Required. |
| `rules[].action` | `allow` \| `reject` \| `rewrite` | Required. |
| `rules[].reason` | string | Required iff action is `reject`. |
| `rules[].content` | string (CEL → map) | Required iff action is `rewrite`. |
| `rules[].onError` | `skip` \| `reject` | Optional; behavior on CEL eval error. Defaults: `reject` for reject rules, `skip` otherwise (see Error handling). |

### JSON Schema

`config.schema.json` (JSON Schema draft 2020-12) ships in the repo root and
is embedded in the binary. It encodes: allowed top-level keys
(`additionalProperties: false`), enums for `defaultAction`, `action`, and
`onError`,
required fields, and conditional requirements via `allOf`/`if`/`then`
(`reject` → `reason` required; `rewrite` → `content` required). Editors pick
it up through the `yaml-language-server` modeline; the loader validates
against the same schema before CEL compilation so structural errors and
expression errors are reported distinctly.

## Error handling

- Startup: schema violation or CEL compile error → exit non-zero with the
  offending rule name and position.
- Runtime CEL evaluation error (missing field, type mismatch): behavior is
  per-rule via an optional `onError: skip | reject` key. Defaults are
  fail-safe by action: rules with `action: reject` default to
  `onError: reject` (an error in a security rule must not become an allow),
  rules with `action: allow`/`rewrite` default to `onError: skip` (warn and
  continue down the chain). Error-rejects use the rule's `reason` if set,
  else a generic "policy evaluation error" reason. Every eval error is
  logged with rule name and error.
- Rewrite expression evaluating to a non-map: treated as an eval error
  (same `onError` handling).
- Absent or null request `content`: evaluated as an empty map, so `has()`
  guards behave predictably instead of erroring.
- Malformed request body / missing `op` param → HTTP 400. frp treats
  non-200 as an error and rejects the operation (verified in frps
  `pkg/plugin/server/http.go`), which is the safe failure mode.

## Logging

Structured logs via `log/slog` (JSON). One line per decision: op, matched
rule (or "default"), action, and for rejects the reason. Warnings for
evaluation errors.

## Testing

- `internal/policy`: table-driven tests covering first-match-wins ordering,
  allow/reject/rewrite outcomes, defaultAction, ops filtering, `onError`
  defaults and overrides (a failing reject rule must fail closed), rewrite
  type errors, server-side merge field preservation, and the `with()`
  function. Fixtures use real frp `NewProxy`/`Login` payload shapes.
- `internal/config`: valid config loads; schema violations and CEL compile
  errors fail with useful messages.
- `internal/server`: `httptest` round-trips asserting the exact frp response
  envelopes and 400 behavior.

## Release automation

GoReleaser drives releases. Versioning is fully automated from semantic
commits via `svu` (github.com/caarlos0/svu): every push to `main` computes
the next version from conventional-commit history (`fix:` → patch, `feat:`
→ minor, `feat!:`/`BREAKING CHANGE` → major); if it differs from the
current version, the workflow tags and releases in the same run. No manual
tags. Note: the tag must be created and consumed inside one workflow —
tags pushed with `GITHUB_TOKEN` do not trigger other workflows (GitHub's
recursion guard), so a separate tagger workflow would never start the
release.

- `.goreleaser.yaml`:
  - `builds`: single build, `CGO_ENABLED=0`, targets `linux/amd64` and
    `linux/arm64` (plus `darwin/arm64` binaries for local use), version
    injected via `-ldflags -X main.version={{.Version}}`, `-trimpath`.
  - `dockers_v2` (the `dockers`/`docker_manifests` pair is deprecated in
    GoReleaser v2): one entry building a native multi-arch image
    (`linux/amd64` + `linux/arm64`) from the minimal `Dockerfile`
    (distroless/static, non-root, `COPY $TARGETPLATFORM/frp-cel-plugin` —
    dockers_v2 lays the prebuilt binaries out per-platform in the build
    context), tagged `ghcr.io/abinnovision/frp-server-plugin-cel:{{ .Version }}`
    and `:latest` with OCI source/version labels; buildx publishes the
    manifest (and an SBOM by default) so `docker pull` resolves the right
    architecture automatically.
  - Archives + `checksums.txt` attached to the GitHub Release; changelog
    from conventional commit history.
- `.github/workflows/release.yaml`: runs on push to `main`
  (`permissions: contents: write, packages: write`). Steps: checkout with
  full history and tags; run `svu next` vs `svu current`; if unchanged,
  stop (nothing release-worthy was merged). Otherwise create and push the
  `v*` tag, set up Go, buildx (`use: buildx` in the `dockers` config for
  reliable `--platform` handling), and QEMU (not strictly required for a
  `COPY`-only Dockerfile with no target-arch `RUN` steps, but included as
  belt-and-suspenders), log into GHCR with `GITHUB_TOKEN`, and run
  `goreleaser release --clean` on the freshly tagged HEAD.
- Local/snapshot builds: `goreleaser release --snapshot --clean` produces
  binaries and images without publishing; no separate multi-stage
  Dockerfile is kept.

## Deliverables

- Go module `github.com/abinnovision/frp-server-plugin-cel` with the packages
  above.
- `config.schema.json` in repo root, embedded via `go:embed`.
- Release automation via GoReleaser (see above): `.goreleaser.yaml`,
  minimal `Dockerfile` (`COPY` binary onto distroless), and
  `.github/workflows/release.yaml` publishing multi-arch images to GHCR.
- `examples/`: Kubernetes `Deployment` + `ConfigMap` running the plugin as
  a sidecar/service next to frps, and the matching `[[httpPlugins]]`
  frps.toml snippet.
- `README.md`: protocol overview, config reference, CEL variable reference,
  example policies.
