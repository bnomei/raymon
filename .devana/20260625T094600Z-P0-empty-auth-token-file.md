DEVANA-FINDING: v1
Priority: P0 | Confidence: high | Security-sensitive: yes | Status: fixed
Location: src/cli.rs:192-194,248-277,1317-1321 | src/cli/http.rs:83-109 | Slug: empty-auth-token-file

# Empty `authToken` in ray.json satisfies remote-auth gate but accepts empty credentials

## Finding

When `ray.json` sets `"authToken": ""`, Raymon treats auth as configured (`auth_token.is_some()`), allows non-loopback binds that would otherwise require `RAYMON_AUTH_TOKEN`, and the HTTP middleware accepts requests whose trimmed bearer/header token is empty.

## Violated Invariant Or Contract

Non-loopback binds must not proceed without real credentials. README states Raymon refuses non-loopback binds without `RAYMON_AUTH_TOKEN`. Empty or whitespace-only tokens must not count as enabled auth.

## Oracle

`env_overrides` ignores empty/whitespace `RAYMON_AUTH_TOKEN` values (`if !value.trim().is_empty()`), but `FileConfig::into_partial` passes `auth_token` through unchanged. `run_server` gates on `config.auth_token.is_none()`, not on trimmed non-empty content.

## Counterexample

1. `ray.json`: `{ "host": "0.0.0.0", "authToken": "" }`
2. Start with `RAYMON_ALLOW_REMOTE=1`
3. Server binds successfully (`auth_enabled = true` in startup logs)
4. `POST /` with `Authorization: Bearer ` (empty bearer after trim) returns 200 on ingest instead of 401

## Why It Might Matter

Remote Raymon instances can be exposed on `0.0.0.0` while any client sending an empty bearer token gains full ingest and MCP access. This defeats the documented remote-auth requirement.

## Proof

**Contract mismatch:** `env_overrides` (lines 1162-1165) rejects empty tokens; `PartialConfig::merge` (lines 192-194) and `FileConfig::into_partial` (line 276) store `Some("")` from file config. `run_server` (lines 1317-1321) checks only `is_none()`. `auth_middleware` (lines 104-106) compares trimmed client token to untrimmed `expected`, so `Some("")` matches empty bearer.

## Counterevidence Checked

CLI overrides never set `auth_token`. Non-empty tokens work in `root_fallback_and_direct_mcp_require_auth` tests. Loopback-only default host does not trigger remote gate unless operator changes host.

## Suggested Next Step

Reject empty/whitespace `auth_token` at config merge (file and env), matching env behavior; treat whitespace-only file tokens as unset.

## Agent Handoff

After working this report, preserve the original finding body. Update line 2 `Status: ...` and the final `DEVANA-SUMMARY:` status. Use one of: `open`, `fixed`, `invalid`, `stale`, `duplicate`, `wontfix`. Add dated notes below with the evidence checked.

## Status Notes

- 2026-06-25: open by Devana. Initial report written from static source inspection.
- 2026-06-26: fixed. `FileConfig::into_partial` now filters empty/whitespace-only `auth_token` to `None` (`self.auth_token.filter(|token| !token.trim().is_empty())`), matching the existing env-override behavior. This makes `run_server`'s `is_none()` gate refuse non-loopback binds and prevents `auth_middleware` from accepting empty bearer tokens. Note: the file-config key is snake_case `auth_token` (there is no `authToken` serde alias, unlike other camelCase-aliased keys), so the report's literal `"authToken"` counterexample never parsed; the vulnerability applied to `"auth_token": ""`. Added regression test `empty_file_auth_token_is_treated_as_unset` covering empty, whitespace-only, and valid tokens.

DEVANA-KEY: src/cli.rs:192-194 | P0 | empty-auth-token-file
DEVANA-SUMMARY: Status=fixed | P0 high src/cli.rs:192-194 - Empty auth_token in ray.json enabled remote bind while accepting empty bearer tokens; now filtered to None at config load, matching env behavior, with regression test.