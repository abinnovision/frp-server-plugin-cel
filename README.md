# frp-server-plugin-cel

A server-side policy engine for [frp](https://github.com/fatedier/frp) that evaluates CEL rules to allow, reject, or rewrite lifecycle operations. The plugin integrates with frp's `[[httpPlugins]]` interface and runs as a lightweight sidecar, making authorization and content transformation decisions on `Login`, `NewProxy`, and other frp operations in real time.

## Quick Start

### 1. Create a configuration file

```yaml
# config.yaml
# yaml-language-server: $schema=https://raw.githubusercontent.com/abinnovision/frp-server-plugin-cel/main/config.schema.json
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
    content: content.with({"bandwidth_limit": "1MB"})
```

### 2. Run the plugin

```bash
docker run -v $(pwd)/config.yaml:/etc/frp-cel-plugin/config.yaml \
  -p 127.0.0.1:9001:9001 \
  ghcr.io/abinnovision/frp-server-plugin-cel:latest
```

### 3. Configure frps

Add the plugin reference to your `frps.toml`:

```toml
[[httpPlugins]]
name = "frp-cel-plugin"
addr = "127.0.0.1:9001"
path = "/handler"
ops = ["Login", "NewProxy"]
```

See `examples/frps-httpplugins.toml` for the complete snippet. For a Kubernetes deployment with the plugin as a sidecar, see `examples/kubernetes.yaml`.

## Configuration Reference

The plugin is configured via a single YAML file (typically mounted as a Kubernetes ConfigMap or local file). All fields are optional and default as shown below.

| Field | Type | Default | Description |
|---|---|---|---|
| `bind` | string | `":9001"` | Server listen address. |
| `path` | string | `"/handler"` | HTTP handler path; frp sends `POST` requests here. |
| `defaultAction` | `allow` \| `reject` | `allow` | Action taken when no rule matches the operation. |
| `defaultRejectReason` | string | `"rejected by default policy"` | Reason sent to frp when a default reject occurs. |
| `rules` | array | — | List of policy rules; evaluated in order, first match wins. |

Each rule in `rules` has the following structure:

| Field | Type | Required | Description |
|---|---|---|---|
| `name` | string | yes | Unique rule identifier; used in logs and error messages. |
| `ops` | string[] | yes | frp operation names to which this rule applies (e.g., `["Login", "NewProxy"]`). Unknown op names are accepted for forward compatibility. |
| `when` | string (CEL) | yes | CEL expression evaluating to boolean; rule matches if true. |
| `action` | `allow` \| `reject` \| `rewrite` | yes | Decision type: allow the operation, reject it, or rewrite its content. |
| `reason` | string | for `reject` | Reason message sent to frp when rejecting. |
| `content` | string (CEL) | for `rewrite` | CEL expression evaluating to a map; the result is shallow-merged onto the original operation content. |
| `onError` | `skip` \| `reject` | no | Behavior when the `when` or `content` expression fails at runtime. Defaults: `reject` for reject-action rules (fail closed), `skip` for others. |

### JSON Schema and Editor Support

A JSON Schema (`config.schema.json`) is embedded in the binary and available at https://raw.githubusercontent.com/abinnovision/frp-server-plugin-cel/main/config.schema.json. Add the yaml-language-server modeline to your config file for IDE autocomplete:

```yaml
# yaml-language-server: $schema=https://raw.githubusercontent.com/abinnovision/frp-server-plugin-cel/main/config.schema.json
```

## CEL Reference

Policy rules are written in [CEL (Common Expression Language)](https://github.com/google/cel-go), a simple expression language designed for policies. Each rule evaluation has access to two global variables.

### Variables

- **`op`** (string) — The frp operation name, e.g., `"Login"`, `"NewProxy"`, `"Ping"`.
- **`content`** (map) — The request body's `content` object as decoded from JSON, preserving frp's exact structure. For example, a `NewProxy` request contains `content.proxy_name`, `content.custom_domains`, `content.bandwidth_limit`, etc.

### Built-in Functions

CEL provides standard macros and operators. The following string functions are particularly useful in frp policies:

- **`endsWith(string, string) → bool`** — CEL built-in; check if a string ends with a suffix.
- **`startsWith(string, string) → bool`** — CEL built-in; check if a string starts with a prefix.
- **`contains(string, string) → bool`** — CEL built-in; check if a string contains a substring.
- **`matches(string, regexp) → bool`** — CEL built-in; check if a string matches a regular expression.

The strings extension library adds:

- **`split(string, string) → list`** — Split a string by separator.
- **`join(list, string) → string`** — Join list elements with a separator.
- **`replace(string, string, string) → string`** — Replace all occurrences.
- **`format(string, ...args) → string`** — Printf-style formatting.

### Content Transformation: `with()`

Rewrite actions use a custom `with()` function to safely merge new fields into the content:

```cel
content.with({"bandwidth_limit": "1MB", "proxy_type": "tcp"})
```

This performs a shallow merge, overlaying the argument map onto `content` and returning the result. The original `content` is never modified. In rewrite actions, the result of the `content` expression is always shallow-merged server-side onto the original request content, so partial rewrites (e.g., `{"bandwidth_limit": "1MB"}`) are safe — they will not zero fields like `proxy_name` or `custom_domains`.

### Examples

```cel
# Allow any operation
true

# Reject unless the user is from a whitelist
!(content.user.user in ["alice", "bob"])

# Condition that triggers a CI bandwidth rewrite
content.user.user == "ci-bot"
```

The domain-restriction pattern is shown in full under [Example Policies](#example-policies).

## Semantics and Caveats

### First Match Wins

Rules are evaluated in configuration file order. The first rule whose `when` condition evaluates to `true` determines the outcome. No further rules are evaluated.

### Error Handling

When a CEL expression fails at runtime (e.g., accessing a non-existent field, type mismatch), behavior depends on the rule's `onError` setting:

- **Reject rules** (`action: reject`) default to `onError: reject` — they fail closed, rejecting the operation. An error in a security rule must not silently allow a request.
- **Allow and rewrite rules** default to `onError: skip` — they log a warning and continue to the next rule.

This behavior can be overridden explicitly in the rule configuration.

### CloseProxy Operations

The frp server discards plugin responses for the `CloseProxy` operation. Rules targeting `CloseProxy` with `reject` or `rewrite` actions will match and execute, but their decisions are not applied; they serve observability purposes only. The plugin logs a warning for such rules at startup.

### Network Security

The frp plugin protocol is unauthenticated plaintext HTTP. In production:

- **Deploy the plugin as a sidecar** on the same host or pod as frps, so frps reaches it at `127.0.0.1:9001` without crossing network boundaries.
- **Use Kubernetes NetworkPolicy** to restrict traffic to the plugin port if it must be exposed across pods.
- **Never expose the plugin port to untrusted networks.** Anyone who can reach the plugin can trigger policy decisions.

### Healthz Endpoint

The plugin serves `GET /healthz` on the configured `bind` address/port, returning `200 OK` with body `"ok"` when healthy; `path` only affects the plugin handler route, not the healthz endpoint. Use this endpoint in Kubernetes readiness and liveness probes.

## Example Policies

### 1. Restrict Custom Domains

Only allow `NewProxy` requests whose custom domains fall under an approved zone:

```yaml
- name: restrict-custom-domains
  ops: [NewProxy]
  when: |
    has(content.custom_domains) &&
    !content.custom_domains.all(d, d.endsWith(".tunnels.example.com"))
  action: reject
  reason: "custom_domains must be under *.tunnels.example.com"
```

This rule rejects any `NewProxy` request that either lacks `custom_domains` or has any domain outside `*.tunnels.example.com`. It uses CEL's `all()` macro to check every domain in the list.

### 2. Force Bandwidth Limit for CI

Automatically impose a bandwidth limit on connections from the CI service:

```yaml
- name: force-ci-bandwidth-limit
  ops: [NewProxy]
  when: "content.user.user == 'ci-bot'"
  action: rewrite
  content: content.with({"bandwidth_limit": "1MB"})
```

When frps forwards a `NewProxy` request from the `ci-bot` user, the plugin rewrites the proxy config to add a 1 MB/s bandwidth limit, even if the original request omitted it or requested a higher limit.

### 3. Require Authentication Metadata on Login

Reject login attempts that lack a required metadata key:

```yaml
- name: require-team-metadata
  ops: [Login]
  when: "!(has(content.metas) && has(content.metas.team))"
  action: reject
  reason: "Login requires 'team' metadata key"
```

This rule enforces that all clients provide a `metas.team` field during the `Login` handshake. `has()` only guards its immediate argument, so checking `has(content.metas.team)` alone would still error (and reject via the `onError` path) when `metas` is absent entirely; checking `has(content.metas)` first short-circuits that case. If a client tries to log in without the field, the login is rejected server-side before the connection is established.

## Releases

Versioning and releases are fully automated. Every push to `main` that includes semantic commits triggers an automatic release if the version has changed.

### Version Computation

The project uses [`svu` (Semantic Versioning Utility)](https://github.com/caarlos0/svu) to compute versions from conventional commit history:

- **`fix:` commits** → patch version bump (e.g., `v1.0.0` → `v1.0.1`)
- **`feat:` commits** → minor version bump (e.g., `v1.0.0` → `v1.1.0`)
- **`feat!:` or `BREAKING CHANGE` commits** → major version bump (e.g., `v1.0.0` → `v2.0.0`)

### Commit Message Format

Use [Conventional Commits](https://www.conventionalcommits.org/) for all commits:

```
feat: add support for custom CEL functions
fix: resolve race condition in policy engine
docs: update README with examples
```

Commit style therefore matters: releases are driven by commit message prefixes, not manual tags.

### Release Artifacts

When a release is published, the following artifacts are created:

- **Container images**: Multi-architecture images (`linux/amd64` and `linux/arm64`) published to GitHub Container Registry:
  - `ghcr.io/abinnovision/frp-server-plugin-cel:v1.2.3` (version tag)
  - `ghcr.io/abinnovision/frp-server-plugin-cel:latest` (latest tag)
- **Binaries**: Native binaries for `linux/amd64`, `linux/arm64`, and `darwin/arm64` attached to the GitHub Release, along with checksums.
- **Changelog**: Automatically generated from conventional commit history.

There are no separate per-architecture image tags like `v1.2.3-amd64` or `v1.2.3-arm64`; use the platform-agnostic tags above and let your container runtime resolve the correct architecture.

### Deploying a New Release

To release a new version:

1. Make your changes on a branch and create a pull request.
2. Merge the PR to `main` with squashed conventional commits (or ensure the merge commit itself follows the convention).
3. The release workflow runs automatically, detects the version change, creates a git tag, and publishes artifacts.
4. Wait for the GitHub Actions workflow to complete, then pull the new image:

```bash
docker pull ghcr.io/abinnovision/frp-server-plugin-cel:latest
```
