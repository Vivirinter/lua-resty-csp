# lua-resty-csp

Content Security Policy (CSP) builder for OpenResty.

## Installation

```bash
opm install Vivirinter/lua-resty-csp
```

Or manually copy `lib/resty/csp.lua` to your OpenResty lualib directory.

## Usage

```lua
local csp = require("resty.csp")

-- Using presets
csp.strict():apply()

-- Custom policy
csp.new()
    :default_src(csp.SELF)
    :script_src(csp.SELF, "cdn.jsdelivr.net")
    :style_src(csp.SELF, csp.UNSAFE_INLINE)
    :img_src(csp.SELF, csp.DATA)
    :apply()

-- From config table
csp.from({
    default_src = {"'self'"},
    script_src = {"'self'", "cdn.example.com"},
}):apply()
```

## Presets

- `csp.strict()` — Maximum security
- `csp.basic()` — Allows unsafe-inline styles
- `csp.api()` — Minimal policy for JSON APIs

## Constants

`csp.SELF`, `csp.NONE`, `csp.UNSAFE_INLINE`, `csp.UNSAFE_EVAL`, `csp.DATA`, `csp.BLOB`

## API

| Method | Description |
|--------|-------------|
| `csp.new()` | Create empty policy |
| `:default_src(...)` | Set default-src |
| `:script_src(...)` | Set script-src |
| `:style_src(...)` | Set style-src |
| `:img_src(...)` | Set img-src |
| `:apply()` | Set HTTP header |
| `:build()` | Get CSP string |
| `:clone()` | Copy policy |
| `csp.nonce(value)` | Format nonce |
| `csp.generate_nonce()` | Generate random nonce |

## License

MIT

