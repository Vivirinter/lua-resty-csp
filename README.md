# lua-resty-csp

[![CI](https://github.com/Vivirinter/lua-resty-csp/actions/workflows/ci.yml/badge.svg)](https://github.com/Vivirinter/lua-resty-csp/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)

Content-Security-Policy (CSP) header builder for [OpenResty](https://openresty.org/) / ngx_lua.

## Install

```bash
opm get Vivirinter/lua-resty-csp
```

Or copy `lib/resty/csp.lua` into your Lua package path.

## Quick start

```lua
local csp = require("resty.csp")

csp.strict():apply()

csp.new()
    :default_src(csp.SELF)
    :script_src(csp.SELF, "cdn.jsdelivr.net")
    :style_src(csp.SELF, csp.UNSAFE_INLINE)
    :img_src(csp.SELF, csp.DATA)
    :object_src(csp.NONE)
    :apply()
```

Nonce-based scripts:

```lua
local nonce = assert(csp.generate_nonce())
ngx.ctx.csp_nonce = nonce

csp.new()
    :default_src(csp.SELF)
    :script_src(csp.nonce(nonce), csp.STRICT_DYNAMIC)
    :object_src(csp.NONE)
    :base_uri(csp.SELF)
    :apply()
```

```html
<script nonce="...">/* same value as ngx.ctx.csp_nonce */</script>
```

## Presets

| API | Purpose |
|-----|---------|
| `csp.strict()` | Locked-down HTML baseline |
| `csp.basic()` | Common web app defaults (allows `'unsafe-inline'` styles) |
| `csp.api()` | Minimal policy for JSON / API responses |

## API

| Call | Returns |
|------|---------|
| `csp.new()` | empty policy |
| `csp.from(table)` | `policy, err` |
| `csp.from_json(str)` | `policy, err` |
| `csp.from_file(path)` | `policy, err` |
| `:default_src(...)` / `:script_src(...)` / … | fluent setters |
| `:set(directive, ...)` | replace directive |
| `:remove(directive)` / `:clear()` | mutate |
| `:report_only([bool])` | Report-Only header mode |
| `:clone()` / `:merge(other)` | copy / merge |
| `:build()` | header value string |
| `:header()` | `name, value` |
| `:apply()` | set `ngx.header` → `self, err` |
| `csp.nonce(value)` | `'nonce-…'` source |
| `csp.generate_nonce([len])` | `nonce, err` |
| `csp.hash(algo, content)` | `expr, err` (needs `resty.sha*`) |
| `csp.parse_report(body)` | parsed report table |
| `csp.report_handler(cb)` | OpenResty content handler |

`from()` rejects unknown keys. Use `report_only = true` in the config table when needed.

## Examples

- [`examples/nginx.conf`](examples/nginx.conf) — full server snippet with nonce
- [`examples/basic.lua`](examples/basic.lua) — preset usage
- [`examples/nonce.lua`](examples/nonce.lua) — nonce + strict-dynamic
- [`examples/from_config.lua`](examples/from_config.lua) — table / JSON config
- [`examples/report.lua`](examples/report.lua) — violation report endpoint

## Development

```bash
make test
make test-resty
make test-nginx   # requires OpenResty + Test::Nginx
```

CI runs unit tests, `resty` tests in Docker, and `Test::Nginx` on every push to `main`.

## License

MIT
