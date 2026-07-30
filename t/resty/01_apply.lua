local csp = require("resty.csp")

local function assert_eq(got, exp, msg)
    if got ~= exp then
        error((msg or "assert_eq") .. ": got=" .. tostring(got) .. " exp=" .. tostring(exp), 2)
    end
end

local function assert_has(s, sub)
    if type(s) ~= "string" or not s:find(sub, 1, true) then
        error("missing " .. tostring(sub) .. " in " .. tostring(s), 2)
    end
end

assert_eq(csp._VERSION, "0.3.0")

local headers = {}
ngx.header = setmetatable({}, {
    __newindex = function(_, k, v) headers[k] = v end,
    __index = function(_, k) return headers[k] end,
})

local policy = csp.strict()
local ok, err = policy:apply()
assert(ok == policy, err)
assert_has(headers["Content-Security-Policy"], "default-src 'none'")
assert_has(headers["Content-Security-Policy"], "object-src 'none'")

headers = {}
local nonce = assert(csp.generate_nonce(16))
assert_eq(#nonce, 16)

csp.new()
    :default_src(csp.SELF)
    :script_src(csp.nonce(nonce), csp.STRICT_DYNAMIC)
    :object_src(csp.NONE)
    :apply()

assert_has(headers["Content-Security-Policy"], "'nonce-" .. nonce .. "'")
assert_has(headers["Content-Security-Policy"], "'strict-dynamic'")

local digest, herr = csp.hash("sha256", "alert(1)")
assert(type(digest) == "string", herr)
assert_has(digest, "'sha256-")

headers = {}
csp.api():report_only(true):apply()
assert(headers["Content-Security-Policy-Report-Only"] ~= nil)

io.write("resty tests ok\n")
