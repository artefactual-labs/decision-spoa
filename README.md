# decision-spoa

`decision-spoa` is a Go-based Stream Processing Offload Agent (SPOA) for HAProxy. It evaluates incoming requests against Artefactual’s policy rules, enriches them with GeoIP data, and returns the actions HAProxy should apply (bucket, JavaScript challenge, varnish routing, reason code). The project also ships a companion CLI to download and refresh the MaxMind databases used by the agent.

- Policy decisions are determined by backend/frontend defaults plus rule evaluations in `internal/policy`.
- GeoIP lookups rely on the MaxMind City and ASN databases and can be hot-reloaded with `SIGHUP`.
- Prometheus metrics report policy outcomes, rule hits, and GeoIP lookup telemetry.

## Binaries

| Command | Description |
| --- | --- |
| `decision-spoa` | The SPOA daemon HAProxy connects to. |
| `decision-geoip-db-updates` | Helper CLI that downloads and swaps the GeoIP databases atomically. |
| `decision-configcheck` | Validates a policy directory without starting the daemon (think `nginx -t`). |

Both binaries expose `-h` for full flag usage. Every flag also has an equivalent environment variable (see below).

## Requirements

- Go 1.25+
- MaxMind GeoLite2 City and ASN databases (optional but recommended)
- HAProxy 2.0+ with SPOE support

## Building

```bash
make build
```

The Makefile produces stripped binaries in `./build/`. It also injects version, commit, and build date metadata sourced from the local git checkout.

To build manually:

```bash
env GOTOOLCHAIN=local go build -trimpath -o build/decision-spoa ./cmd/decision-spoa
env GOTOOLCHAIN=local go build -trimpath -o build/decision-geoip-db-updates ./cmd/decision-geoip-db-updates
env GOTOOLCHAIN=local go build -trimpath -o build/decision-configcheck ./cmd/decision-configcheck
```

## Running the SPOA

```bash
./build/decision-spoa \
  --listen 127.0.0.1:9908 \
  --metrics 127.0.0.1:9907 \
  --root /etc/decision-policy \
  --city-db /var/lib/GeoIP/GeoLite2-City.mmdb \
  --asn-db /var/lib/GeoIP/GeoLite2-ASN.mmdb
```

Append `--check-config` to validate the policy directory and exit without starting the service.

The Debian/RPM packages install a `decision-spoa.service` systemd unit that uses `/etc/default/decision-spoa` to pass CLI options. The stock configuration listens on `127.0.0.1:9908`, exposes metrics on `127.0.0.1:9907`, and enables best-effort GeoIP downloads. Optional high-cardinality metrics (`--metrics-host-label`, `--metrics-geoip`) remain disabled unless explicitly added to `DECISION_SPOA_OPTS`.

### Flags and environment variables

| Flag | Env var | Default | Notes |
| --- | --- | --- | --- |
| `--listen` | `DECISION_LISTEN` | `127.0.0.1:9107` | TCP address HAProxy connects to (packages override to `127.0.0.1:9908`). |
| `--metrics` | `DECISION_METRICS` | `127.0.0.1:9907` | Prometheus HTTP endpoint (`/metrics`). |
| `--root` | `DECISION_ROOT` | `/etc/decision-policy` | Directory containing policy config files. |
| `--debug` | `DECISION_DEBUG` | disabled | Enables verbose policy logs (see below). |
| `--metrics-host-label` | `DECISION_METRICS_HOST_LABEL` | disabled | Adds the `host` label to metrics (higher cardinality). |
| `--metrics-geoip` | `DECISION_METRICS_GEOIP` | disabled | Exports GeoIP metrics (`decision_policy_geo_lookups_total`, country, ASN counters). |
| `--city-db` | `GEOIP_CITY_DB` | `/var/lib/GeoIP/GeoLite2-City.mmdb` | Path to City database. Optional but enables country lookups. |
| `--asn-db` | `GEOIP_ASN_DB` | `/var/lib/GeoIP/GeoLite2-ASN.mmdb` | Path to ASN database. |
| `--city-url` | `GEOIP_CITY_URL` | empty | Download URL consumed by the update helper. |
| `--asn-url` | `GEOIP_ASN_URL` | empty | Download URL consumed by the update helper. |
| `--best-effort` | n/a | `true` | Ignore GeoIP download errors when set. |

Send `SIGHUP` to the running process to reload the policy configuration and reopen the GeoIP databases without interrupting HAProxy connections.

#### Debug logging

When `--debug` (or `DECISION_DEBUG`) is enabled the daemon prints an expanded policy line for every SPOE transaction. The log now includes:

- `raw_input`: every key/value HAProxy delivered via SPOE, sorted for readability.
- `src`, `xff`, and `ip`: the TCP peer, the header presented by HAProxy, and the client IP selected after trusted-proxy processing.
- `xff_used`, `xff_stripped`, and `trusted_peer`: whether the XFF header was honoured, how many trusted hops were removed, and if the immediate peer matches the configured `trusted_proxy` list.
- `trusted_entries`: the combined trusted entries (global + frontend + backend) active for the request.

These extras make it easy to confirm that trusted proxy configuration is in effect and to troubleshoot spoofed headers or misconfigured upstreams.

## Packaging

We use GoReleaser + NFPM to ship `.deb`/`.rpm` artifacts. Installing the package provides:

- `decision-spoa.service` and its companion default file at `/etc/default/decision-spoa`.
- `decision-geoip-db-updates.service` plus the daily `decision-geoip-db-updates.timer` and `/etc/default/decision-geoip-db-updates`.
- A sample HAProxy SPOE config at `/etc/haproxy/decision-spoa.cfg`.
- A starter policy at `/etc/decision-policy/policy.yml`.

The post-install hook ensures `/var/lib/decision` and `/etc/decision-policy` exist and are owned by the `haproxy` account, labels TCP ports 9907/9908 as `http_port_t` under SELinux, reloads systemd, and enables both the main service and the GeoIP timer. The package depends on `haproxy` being present so the service account/group already exist.

Editing the default files is the supported way to change runtime flags. The shipped values look like this:

```sh
# /etc/default/decision-spoa
DECISION_SPOA_OPTS="\
  --listen 127.0.0.1:9908 \
  --metrics 127.0.0.1:9907 \
  --root /etc/decision-policy \
  --city-db /var/lib/decision/GeoLite2-City.mmdb \
  --asn-db /var/lib/decision/GeoLite2-ASN.mmdb \
  --city-url https://hub-data.crowdsec.net/mmdb_update/GeoLite2-City.mmdb \
  --asn-url https://hub-data.crowdsec.net/mmdb_update/GeoLite2-ASN.mmdb \
  --best-effort \
  --metrics-host-label"

# /etc/default/decision-geoip-db-updates
DECISION_GEOIP_DB_UPDATES_OPTS="\
  --city-out /var/lib/decision/GeoLite2-City.mmdb \
  --asn-out /var/lib/decision/GeoLite2-ASN.mmdb \
  --city-url https://hub-data.crowdsec.net/mmdb_update/GeoLite2-City.mmdb \
  --asn-url https://hub-data.crowdsec.net/mmdb_update/GeoLite2-ASN.mmdb \
  --best-effort"
```

After editing either file, run `systemctl restart decision-spoa` or trigger the updater manually with `systemctl start decision-geoip-db-updates.service`.

### HAProxy integration

Configure HAProxy to send the fields expected by the agent (`src`, `xff`, `ua`, `host`, `path`, `method`, `query`, `backend`, `frontend`, and optionally `ssl_sni`, `ja3`, `protocol`) via SPOE messages and consume the returned variables:

```haproxy
spoe-agent decision-spoa
    messages policy-eval
    option var-prefix policy
    use-backend policy-servers if TRUE

spoe-message policy-eval
    args \
        ip=src \
        method=method \
        path=path \
        query=query \
        hdr_host=hdr(host) \
        hdr_ua=hdr(User-Agent) \
        xff=hdr(X-Forwarded-For) \
        ssl_sni=ssl_fc_sni \
        ja3=req.fhdr(ssl_fc_ja3_hash)  # optional; requires JA3 support in your build
```

Adapt the example to match your actual frontend/backend architecture and message naming.

## Policy configuration

All policy data now lives in a single YAML document, `policy.yml`, located under `DECISION_ROOT` (default `/etc/decision-policy`). The file has three main sections: defaults, trusted proxy scopes, and an ordered `rules` array. Rules are evaluated in order until the first match; if no rule matches, the `fallback` rule provides the final response.

```yaml
defaults:
  global:
    policy.bucket: default
    policy.challenge: true
    policy.use_varnish: true
  frontends:
    fe_admin:
      policy.bucket: high
      policy.challenge: true
      policy.use_varnish: false
  backends:
    be_api:
      policy.bucket: default
      policy.challenge: false
      policy.use_varnish: true

trusted_proxy:
  global:
    - 192.0.2.10
    - 2001:db8::5
  frontends:
    fe_admin:
      - 198.51.100.11
  backends:
    be_api:
      - 10.0.0.5

rules:
  - name: admin-bypass
    frontends: ["fe_admin"]
    match:
      host: ["^admin\\.example\\.com$"]
      method: ["GET", "POST"]
      user_agent: ["Observatory"]
    return:
      policy.bucket: admin
      policy.challenge: false
      policy.admin_audit: "true"

  - name: static-cache
    protocols: ["http"]
    match:
      path: ["^/static/"]
      sni: ["^static\\.example\\.com$"]  # optional if you capture SNI
    return:
      policy.use_varnish: true
      policy.challenge: false
      reason: static-cache

  - name: fallback
    fallback: true
    return:
      reason: default-policy
```

The fallback entry acts as the safety net when no earlier rule matches. It should describe the baseline decision your HAProxy configuration expects (for example, setting a catch-all reason or toggling an audit flag). You may leave the `return` map empty if the defaults already cover everything; the agent still enforces an implicit `"default-policy"` reason. If you omit the fallback altogether, the compiler injects that implicit rule, so keeping one is optional. Retain it when you want to document the “otherwise” path explicitly or to perform conditional work such as setting a reason only for unmatched traffic while allowing earlier rules to keep their own values.

### Rule reference

The table below lists every key supported inside a `rules:` entry. Unless stated otherwise, omit a field to leave it unconstrained.

| Field | Type | Default | Notes |
| --- | --- | --- | --- |
| `name` | string | empty | Optional identifier surfaced in logs/metrics. |
| `protocols` | list of string | `["http"]` | Allowed protocols for the rule. Values are normalised to lowercase. Combine with `match.protocol` when you prefer to keep the protocol filter alongside other match clauses. |
| `frontends` | list of string | any frontend | Limits evaluation to specific HAProxy frontends. |
| `backends` | list of string | any backend | Limits evaluation to specific HAProxy backends. |
| `match` | mapping | `{}` | Field predicates. See the table below for all available matchers. |
| `return` | mapping (string → value) | required | Variables emitted back to HAProxy. Must contain at least one key. The key `reason` (case-insensitive) is treated specially as the policy reason string. |
| `fallback` | boolean | `false` | Marks the rule as the fallback response. Exactly one rule in the file should set this to `true`. |

`match` supports the following keys. Every slice is OR-ed; leave the list empty to skip that matcher.

| Match key | Type | Notes |
| --- | --- | --- |
| `protocol` | list of string | Same semantics as top-level `protocols`; combined with that list. |
| `host` | list of string | Exact matches when the value lacks regex tokens, or Go regular expressions otherwise. Host names are matched case-insensitively. |
| `path` | list of regex | Go regular expressions evaluated against the HTTP path. |
| `method` | list of string | Case-insensitive exact matches (e.g., `GET`, `POST`). |
| `query` | list of regex | Go regular expressions matched against the raw query string. |
| `xff` | list of regex | Regular expressions matched against the full `X-Forwarded-For` header received from HAProxy. |
| `user_agent` | list of regex | Regular expressions evaluated against the `User-Agent` header. |
| `sni` | list of regex | Regular expressions evaluated against the TLS SNI (requires HAProxy to forward `ssl_fc_sni`). |
| `ja3` | list of regex | Regular expressions evaluated against the JA3 hash (requires `ssl_fc_ja3_hash`). |
| `country` | list of string | ISO 3166-1 alpha-2 country codes compared against the GeoIP lookup result. |
| `asn` | list of uint | ASN numbers compared against the GeoIP lookup result. |
| `cidr` | list of CIDR strings | IPv4/IPv6 ranges checked against the client IP after trusted-proxy stripping. |

Values placed under `return` are merged into the output in declaration order. Regular rules use “first writer wins”: once a variable is set by a matching rule it stays locked for the remainder of the evaluation. The fallback rule runs last with a “fill in the blanks” strategy, only populating keys that were never set earlier.

**Reason string.** The special `reason` key controls the human-readable explanation returned to HAProxy and exported in the `decision_policy_decisions_total{reason=...}` metric. The first matching rule that sets `reason` keeps it locked; fallback only assigns a reason when none was provided earlier. If you omit the key entirely, the agent emits `"default-policy"` as the final reason.

### Defaults precedence

The `defaults` section seeds every evaluation in three layers:

- Start with `defaults.global`.
- If the SPOE transaction came through a named frontend, merge `defaults.frontends[frontend]`.
- Finally, merge `defaults.backends[backend]`.

Because later merges overwrite earlier values, backend-specific defaults win over frontend defaults, and frontend defaults win over the global baseline. If you prefer the frontend settings to take precedence, leave the backend stanza empty or keep the frontend-specific logic inside explicit `rules` entries that run before backend-scoped rules.

### Match semantics

- All match lists are OR-ed. `host` entries default to exact matches unless you include regex tokens (`^`, `*`, `[]`, etc.); `path`, `xff`, `user_agent`, `query`, `sni`, and `ja3` entries are compiled as Go regular expressions.
- `method` comparisons are case-insensitive exact matches (e.g., `GET`, `POST`).
- `sni` and `ja3` clauses are optional—include them only if your HAProxy build exports those fields via SPOE.
- JA3 fingerprints require HAProxy 2.5+ (community builds added `ssl_fc_ja3_hash` in that release). JA4 still needs 2.9+ or an external TLS terminator that forwards the hash. Builds ≤2.4 cannot expose the client hello to SPOE, so leave those matchers out there.
- `country` expects ISO alpha-2 codes. `asn` takes unsigned integers. `cidr` supports IPv4/IPv6 ranges in CIDR notation.
- Scope filters (`frontends`, `backends`, `protocols`) constrain where the rule can run. Omit the field to allow every value. Protocol names are lower-cased strings; `http` is assumed if none are supplied.
- `return` is an arbitrary key/value map. Nothing is reserved—emit whichever variables you intend to consume in HAProxy (e.g., `policy.bucket`, `policy.challenge`, custom flags), and gate behaviour there with `var()` checks.

Always end the file with a `fallback` rule. The agent will merge fallback values with the defaults so you can keep using the existing global/front/back `defaults` structure.

### Validating policy.yml

Use the standalone config checker before deploying changes:

```bash
./build/decision-configcheck --root /etc/decision-policy
```

The command loads and compiles `policy.yml`; it exits non-zero on parse errors, invalid CIDR blocks, bad regular expressions, or missing defaults.

### Rule Design Tips

- Prefer the cheapest checks first. Country/ASN comparisons are fast; regexes over `path`/`query` are slower. Order high-selectivity rules early so traffic exits quickly.
- Use literal matches whenever the field supports them. For `host`, `path`, `user_agent`, and `sni`, list plain strings unless you genuinely need regex tokens—literal matches are faster and easier to reason about.
- When you do need regex, anchor expressions (`^` / `$`) and keep them as narrow as possible to avoid backtracking.
- Keep shared lists small and explicit (e.g., break “cloud” CIDRs into labeled subsets) so operators can reason about impact. Repeatedly referenced sets belong in `shared/` files.
- Watch Prometheus metrics (`decision_policy_rule_hits_total`, `decision_policy_eval_seconds`) after adding rules. Spikes in eval time usually signal expensive regex chains or catch-all matchers firing too often.
- Aim for idempotent merges: set only the variables you need in each rule and rely on defaults for everything else. That keeps config readable and limits accidental overrides.

### HAProxy Integration Example

The snippet below sketches how you might wire this SPOA alongside Coraza (WAF), JS-cookie challenges, and Varnish. Replace placeholders with your actual listener addresses, certificates, and ACLs.

```haproxy
# SPOE agents
spoe-agent decision-spoa
    messages policy-eval
    option var-prefix policy
    use-backend policy-servers if TRUE

spoe-message policy-eval
    args \
        ip=src \
        method=method \
        path=path \
        query=query \
        hdr_host=hdr(host) \
        hdr_ua=hdr(User-Agent) \
        xff=hdr(X-Forwarded-For) \
        ssl_sni=ssl_fc_sni

spoe-agent coraza-waf
    messages coraza-eval

frontend https-in
    bind 0.0.0.0:443 ssl crt /etc/haproxy/certs/example.pem crt /etc/haproxy/certs/example2.pem
    acl host_fqdn1 hdr(host) -i fqdn1.example.com
    acl host_fqdn2 hdr(host) -i fqdn2.example.com
    acl src_exempt_coraza_fqdn1 ip 5.6.7.0/25
    acl src_exempt_coraza_fqdn2 asn 8075          # Azure ASN example

    # Run Coraza unless explicitly exempted
    use-server coraza-waf if ! (host_fqdn1 src_exempt_coraza_fqdn1) ! (host_fqdn2 src_exempt_coraza_fqdn2)

    # Always call the policy SPOA
    use-server decision-spoa

    default_backend policy-router

backend policy-router
    acl want_varnish var(policy.use_varnish) -m bool true
    use_backend varnish-backend if want_varnish
    acl is_fqdn1 var(policy.backend) -i fqdn1
    use_backend fqdn1-backend if is_fqdn1
    use_backend fqdn2-backend

backend varnish-backend
    server varnish1 127.0.0.1:6081

backend fqdn1-backend
    acl skip_js var(policy.challenge) -m bool false
    http-response set-header Set-Cookie "js_challenge=ok; Path=/; Secure" if skip_js
    server fqdn1 127.0.0.1:80

backend fqdn2-backend
    server fqdn2 127.0.0.1:80
```

And the matching `policy.yml` could look like:

```yaml
defaults:
  global:
    policy.use_varnish: true
    policy.use_coraza: true
    policy.challenge: true
    policy.backend: default
  backends:
    fqdn1:
      policy.backend: fqdn1
    fqdn2:
      policy.backend: fqdn2

trusted_proxy:
  global: []

rules:
  - name: allow-search-bots
    match:
      asn: [15169, 8075]
      user_agent:
        - '(?i)googlebot'
        - '(?i)bingbot'
    return:
      policy.challenge: false
      reason: allow-search-bots

  - name: block-cn
    match:
      country: [CN]
    return:
      policy.bucket: deny
      policy.challenge: false
      policy.use_varnish: false
      reason: deny-cn

  - name: skip-js-canada-azure
    match:
      country: [CA]
      asn: [8075]
    return:
      policy.challenge: false
      reason: skip-js-ca-azure

  - name: fqdn1-us-no-challenge
    backends: [fqdn1]
    match:
      country: [US]
    return:
      policy.challenge: false
      reason: fqdn1-us

  - name: fqdn1-ca-force-challenge
    backends: [fqdn1]
    match:
      country: [CA]
    return:
      policy.challenge: true
      reason: fqdn1-ca

  - name: fqdn1-bypass-varnish
    backends: [fqdn1]
    match:
      cidr: ['1.2.3.0/24']
      asn: [16276]          # OVH
    return:
      policy.use_varnish: false
      reason: fqdn1-direct

  - name: fqdn2-chatgpt
    backends: [fqdn2]
    match:
      user_agent: ['ChatGPT']
    return:
      policy.challenge: false
      reason: fqdn2-chatgpt

  - name: fqdn2-no-varnish
    backends: [fqdn2]
    return:
      policy.use_varnish: false
      reason: fqdn2-direct

  - name: fe-fqdn1-coraza-exempt
    frontends: [https-in]
    match:
      host: ['^fqdn1\.example\.com$']
      cidr: ['5.6.7.0/25']
    return:
      policy.use_coraza: false
      reason: coraza-exempt-fqdn1

  - name: fe-fqdn2-coraza-azure
    frontends: [https-in]
    match:
      host: ['^fqdn2\.example\.com$']
      asn: [8075]
    return:
      policy.use_coraza: false
      reason: coraza-exempt-fqdn2

  - name: fallback
    fallback: true
    return:
      reason: default-policy
```

In HAProxy you can then gate behaviors with `var(policy.use_coraza) -m bool true`, `var(policy.challenge)`, etc., only acting when the variable exists. This keeps the SPOA fully declarative and leaves all enforcement to HAProxy. When you need a new signal, just add a key in the policy output and wire it into the HAProxy ACLs.

- `shared/country/eu.yml`

  ```yaml
  name: eu
  country:
    - AT
    - BE
    - DE
    - ES
    - FR
    - NL
  ```

- `shared/user-agent/bots.yml`

  ```yaml
  name: bots
  user_agent:
    - googlebot
    - bingbot
    - duckduckbot
    - lighthouse
  ```

- `default/cache/url-path.yml`

  ```yaml
  rules:
    - match:
        path_prefix: /assets/
      action:
        use_varnish: true
        challenge: false
        reason: assets-cache
    - match:
        path_suffix: .js
      action:
        use_varnish: true
        reason: js-cache
  ```

- `default/js-challenge/asn-user-agent.yml`

  ```yaml
  rules:
    - match:
        asn_list: shared/asn/high-risk
      action:
        bucket: high
        challenge: true
        reason: challenge-high-risk-asn
    - match:
        user_agent_contains: curl
      action:
        challenge: true
        reason: curl-clients
    - match:
        user_agent_list: shared/user-agent/bots
      action:
        challenge: false
        reason: known-bot
  ```

- `default/rate-limits/country.yml`

  ```yaml
  rules:
    - match:
        country_list: shared/country/eu
      action:
        bucket: medium
        reason: eu-limit
        limit:
          burst: 250
          interval: 1m
    - match:
        country: CN
      action:
        bucket: high
        reason: cn-limit
        limit:
          burst: 50
          interval: 1m
  ```

- `default/allow-deny/ip-cidr.yml`

  ```yaml
  rules:
    - match:
        cidr_list: shared/cidr/cloud
      action:
        bucket: deny
        challenge: false
        reason: deny-cloud
  actions:
    terminal: true
  ```

- `frontends/fe_admin/js-challenge/user-agent.yml`

  ```yaml
  rules:
    - match:
        user_agent_contains: Mozilla
      action:
        challenge: false
        reason: admin-browser
    - match:
        user_agent_regex: (?i)curl|httpie
      action:
        challenge: true
        reason: cli-admin-block
  ```

- `backends/be_api/rate-limits/ip-cidr.yml`

  ```yaml
  rules:
    - match:
        cidr: 203.0.113.44/32
      action:
        challenge: false
        bucket: default
        reason: partner-ip
    - match:
        cidr_list: shared/cidr/cloud
      action:
        bucket: high
        reason: api-cloud-limit
        limit:
          burst: 20
          interval: 1m
  ```

- `backends/be_static/cache/url-path.yml`

  ```yaml
  rules:
    - match:
        path_suffix: .svg
      action:
        use_varnish: true
        challenge: false
        reason: svg-cache
    - match:
        path_prefix: /dynamic/
      action:
        use_varnish: false
        reason: dynamic-bypass
  ```

"`<scope>`" expands to:

- `default/` — base rules applied to every request unless a frontend/backend rule overrides them.
- `frontends/<frontend-name>/` — only evaluated for requests routed through the named HAProxy frontend. Use this to loosen or tighten policies for a specific entry point (e.g., admin UI).
- `backends/<backend-name>/` — highest precedence. Use for per-service exceptions (e.g., allow an API endpoint to bypass caches).

Rules cascade according to scope precedence (**backend ➜ frontend ➜ default ➜ global default**). Within a scope, evaluation is ordered and still honours the “first writer wins” behaviour: once a variable is set by an earlier match it stays locked for the rest of the evaluation. When a scope has no files for a given engine, evaluation falls back to the next scope automatically.

Trusted proxy lists follow the same precedence: global entries are always applied, then frontend-specific entries (if the request came through that frontend), and finally backend-specific entries. The agent strips every matching trailing hop from `X-Forwarded-For` so rule matching always sees the true client IP.

Policy evaluation order and Prometheus instrumentation live in `internal/policy/engine.go`; extend this package when introducing new rule types or actions.

## GeoIP database refresh helper

The `decision-geoip-db-updates` utility downloads GeoLite tarballs or raw `.mmdb` files, compares them by SHA-256 hash, and atomically replaces the on-disk files.

```bash
./build/decision-geoip-db-updates \
  --city-url https://example/GeoLite2-City.mmdb.tar.gz \
  --asn-url https://example/GeoLite2-ASN.mmdb.tar.gz \
  --city-out /var/lib/GeoIP/GeoLite2-City.mmdb \
  --asn-out /var/lib/GeoIP/GeoLite2-ASN.mmdb
```

With `--best-effort` (or the default), the helper exits successfully even when the remote files are unavailable or unchanged.

## Observability

- Prometheus metrics are exposed at `http://<metrics addr>/metrics`.
- Key series include:
  - `decision_policy_decisions_total{backend,host?,bucket,reason}`
  - `decision_policy_rule_hits_total{backend,host?,rule}`
  - `decision_policy_eval_seconds`
  - `decision_policy_geo_lookups_total{outcome}` with outcomes `ok`, `error`, or `no_db`
  - `decision_policy_country_hits_total{country}`
  - `decision_policy_asn_hits_total{asn}`
  - `decision_policy_xff_trusted_strips_total{backend,host?}` (count of XFF hops removed via trusted lists)

Leave the host label and GeoIP metrics disabled unless you are troubleshooting (`--metrics-host-label`, `--metrics-geoip`).

## Upgrade guide

1. Update systemd units, container entrypoints, and HAProxy configs to call the new binaries (`decision-spoa`, `decision-geoip-db-updates`, `decision-configcheck`). The CLI flags are unchanged.
2. Export the new environment variables (`DECISION_LISTEN`, `DECISION_METRICS`, `DECISION_ROOT`, `DECISION_DEBUG`, `DECISION_METRICS_HOST_LABEL`) if you override defaults.
3. Refresh HAProxy SPOE declarations so they reference the new agent name if you mirrored the binary name in config snippets (for example, `spoe-agent decision-spoa`).
4. Point dashboards and alerts at the `decision_policy_*` Prometheus series.
5. Update Go callers/imports to the new module path (`github.com/artefactual-labs/decision-spoa`) before building downstream tooling.

## Development

- Run unit tests: `go test ./...`
- Linting / formatting: follow standard Go tooling (`go fmt`, `go vet`) as needed.
- The project targets Go 1.21; update `go.mod` and CI/CD pipelines accordingly when upgrading.

## License

This project is distributed under the terms of the GNU Affero General Public License v3.0 (see `LICENSE`).
