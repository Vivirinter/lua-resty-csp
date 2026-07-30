package = "lua-resty-csp"
version = "0.3.0-1"
source = {
    url = "git+https://github.com/Vivirinter/lua-resty-csp.git",
    tag = "v0.3.0",
}
description = {
    summary = "Content-Security-Policy (CSP) header builder for OpenResty",
    detailed = [[
        Build and apply Content-Security-Policy response headers from Lua
        in OpenResty / ngx_lua: fluent API, presets, nonces, hashes, reports.
    ]],
    homepage = "https://github.com/Vivirinter/lua-resty-csp",
    license = "MIT",
}
dependencies = {
    "lua >= 5.1",
}
build = {
    type = "builtin",
    modules = {
        ["resty.csp"] = "lib/resty/csp.lua",
    },
}
