local csp = require("resty.csp")

local policy, err = csp.from({
    default_src = { "'self'" },
    script_src  = { "'self'", "cdn.example.com" },
    style_src   = { "'self'", "'unsafe-inline'" },
    object_src  = { "'none'" },
    upgrade_insecure_requests = true,
    report_only = false,
})

if not policy then
    ngx.log(ngx.ERR, err)
    return ngx.exit(500)
end

policy:apply()
