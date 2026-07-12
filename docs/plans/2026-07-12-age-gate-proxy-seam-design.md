# Age-Gate Proxy-Service Seam Design (#2264)

**Goal:** Move age-gate **download** enforcement from the per-format handler layer into the proxy-service layer, where the #1770 quarantine hold already lives, so every serve path — direct, virtual, nested, cache-hit, redirect — is covered by construction instead of by each handler remembering to call the gate. Listing/index filtering stays in handlers (format-specific). This is the durable consolidation requested in [#2264](https://github.com/artifact-keeper/artifact-keeper/issues/2264); the motivating incident is that the virtual paths were missed in the original #2066 PR (fixed by `4f9b31c0`, adopted as `eee4479b`).

**Non-goals for the seam PR:** no new formats, no new gate modes, no behavior change for npm/pypi. Strictly behavior-preserving: every existing `age_gate_tests` case passes unchanged; the `4f9b31c0` virtual tests are the baseline regression net. Format expansion (Go, NuGet, `first_seen` mode) lands afterwards on top of the seam, one PR per slice.

## Design findings (verified on main @ v1.5.3, `ed443b96`)

### 1. The boundary cannot trust its `Repository` argument

Nearly all handler fetches route through `proxy_helpers::with_proxy_repo`, which synthesizes a minimal `Repository` via `build_remote_repo(id, key, upstream_url)` with hardcoded `format: Generic` and `age_gate_enabled: false`. A boundary gate that reads config off the passed struct silently **fails open** on exactly the paths #2264 wants covered.

Quarantine already solves this: `quarantine_until_for_new_entry` re-resolves policy from the DB by `repository_id` (`quarantine_service::resolve_config`) and never trusts the struct. The age gate must do the same — resolve `(repo_type, format, age_gate_enabled, age_gate_min_age_days)` by `repo.id` at the boundary on every gated request.

**No config caching in the first seam PR.** A failed DB lookup must fail the request rather than impersonate `enabled = false`, and enabling a gate or raising its threshold must take effect immediately. If the hot path later warrants a cache, add it with explicit write-side invalidation or a config revision, plus tests for enable- and threshold-change visibility. Cost parity today: the handler-layer gate already does a per-read review-row query in `AgeGateService::check`.

### 2. Path classification lives inside the boundary, keyed by the DB-resolved format

The alternative — handlers pass a gate context `(package, version)` into fetch calls — recreates the bug class that motivated #2264: the virtual per-member loops call the same fetch helpers and would have to remember to build the context, which is exactly the miss `4f9b31c0` fixed.

Instead: a per-format pure classifier registry, `formats::classify_download_path(format, cache_path)`, invoked by the proxy service using the format resolved in finding 1. It is **tri-state**:

- `Metadata` — bypasses the download gate (index/listing/registration documents; also the `upstream_metadata` resolver fetches themselves, so publish-time resolution cannot recurse).
- `Artifact { package, version }` — enters the gate.
- `InvalidArtifactPath` — an artifact-shaped path whose coordinates cannot be parsed is **rejected**, never treated as metadata. Collapsing this case into `None = metadata` would turn today's npm/PyPI fail-closed parse errors into ungated fetches.

An enabled gate on a format with no registered classifier is a configuration error, never an implicit allow. Download paths for npm/pypi (and later go/nuget) encode name+version in the canonical `cache_path`; the classifiers consolidate parsing that already exists piecemeal (e.g. `NpmHandler::extract_version_from_filename`). This same `path -> (package, version)` mechanism is what a future block-only sub-mode for signed-index formats (apk/rpm/deb, where listings cannot be rewritten without re-signing) needs.

### 3. The serve boundary has explicit exceptions that need a call-site inventory

Cache-hit and upstream branches of both buffered and streaming fetches must gate before bytes or headers are committed. Beyond those:

- Redirect/presign producers are more than the two generic quarantine hook sites: `try_member_cache_redirect` and `proxy_fetch_or_redirect` are joined by PyPI's own `pypi_proxy_cache_redirect` and the local/proxy-cache redirect helper.
- A remote PyPI repository can serve a legacy/hydrated `artifacts`-table hit from normal repository storage **without entering `ProxyService` at all**. That path needs a thin call into the same policy evaluator or rerouting through the gated boundary.

Only after these exceptions are covered can the per-handler download-gate helpers (`apply_npm_download_age_gate` / `enforce_pypi_download_age_gate`-style) be deleted. A held (quarantined) object must not be handed out as a redirect or local-storage hit, and neither may an age-blocked one.

## Decision and response propagation

`AgeGateService::check` stays as-is: it is already format-agnostic — `(repo params, package, version, published_at)` — and owns review rows, sticky approvals, and metrics.

Its typed block outcome (`AgeGateBlocked`) must carry the complete decision — review/package/version/age fields **and `last_known_good`** — through `ProxyService` without the `with_proxy_repo`/`map_proxy_error` wrappers erasing it into an HTTP response prematurely. npm/PyPI intercept the typed outcome to build their format-specific LKG substitution path; generic handling maps a no-LKG block to the existing structured 451 body. The LKG re-fetch re-enters the gated boundary, closing "LKG fallback bypasses policy" by construction.

Virtual-member resolution (buffered and streaming) must treat the outcome as **terminal policy enforcement**, like quarantine — not an ordinary member miss. Otherwise a blocked higher-priority member falls through to a lower-priority repository and priority fallthrough becomes a gate bypass.

Publish-time resolution happens at the boundary via the existing `upstream_metadata` fetchers. Missing, malformed, or unreachable publish metadata keeps #2066's fail-closed block behavior; DB/infrastructure errors surface as errors rather than degrading to allow.

## Test matrix for the seam PR

Mirrors the #2066 adoption verification list, plus the failure modes above:

- direct / virtual / nested resolution; proxy-cache hit and miss
- legacy/hydrated `artifacts`-table hit on a remote repo
- generic and PyPI-specific presign redirects
- LKG re-entry through the gated boundary
- Range requests and concurrent fetches
- malformed artifact-shaped path → reject, never metadata
- blocked highest-priority virtual member → no fallthrough
- DB config-read failure → request fails, never allows
- immediate visibility after enabling a gate or raising a threshold

## PR slicing (each `partially fixes #2264`)

1. **Authz quick win** (independent, shipped first): `require_admin()` on `GET /repositories/{key}/age-gate` for parity with the PUT and the /admin review endpoints, plus regression tests.
2. **The seam PR**: boundary enforcement per this design; migrate npm + pypi onto it; delete the per-handler policy implementations once their local-storage exceptions use the shared evaluator; keep all listing filters and format-specific LKG path construction. Behavior-preserving.
3. **Format expansion on the seam**: `first_seen` mode core (observations bound to an upstream/config generation — a same-named version from a newly configured upstream must not inherit the old upstream's elapsed age), then Go, then NuGet; listing filters land per-format, download gates become path classifiers.
