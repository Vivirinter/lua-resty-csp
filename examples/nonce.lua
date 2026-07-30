local csp = require("resty.csp")

local nonce, err = csp.generate_nonce()
if not nonce then
    ngx.log(ngx.ERR, err)
    return ngx.exit(500)
end

ngx.ctx.csp_nonce = nonce

csp.new()
    :default_src(csp.SELF)
    :script_src(csp.nonce(nonce), csp.STRICT_DYNAMIC)
    :object_src(csp.NONE)
    :base_uri(csp.SELF)
    :frame_ancestors(csp.NONE)
    :upgrade_insecure_requests()
    :apply()
