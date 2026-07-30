local _M = {
    _VERSION = "0.3.0",

    SELF             = "'self'",
    NONE             = "'none'",
    UNSAFE_INLINE    = "'unsafe-inline'",
    UNSAFE_EVAL      = "'unsafe-eval'",
    STRICT_DYNAMIC   = "'strict-dynamic'",
    UNSAFE_HASHES    = "'unsafe-hashes'",
    WASM_UNSAFE_EVAL = "'wasm-unsafe-eval'",
    REPORT_SAMPLE    = "'report-sample'",
    DATA             = "data:",
    BLOB             = "blob:",
    HTTPS            = "https:",
}

local DIRECTIVES = {
    "default-src",
    "script-src", "script-src-elem", "script-src-attr",
    "style-src",  "style-src-elem",  "style-src-attr",
    "img-src", "font-src", "connect-src", "media-src", "object-src",
    "frame-src", "child-src", "worker-src", "manifest-src",
    "base-uri", "sandbox", "form-action", "frame-ancestors", "navigate-to",
    "report-uri", "report-to",
    "require-trusted-types-for", "trusted-types",
    "upgrade-insecure-requests", "block-all-mixed-content",
    "prefetch-src",
}

local KNOWN = {}
for i = 1, #DIRECTIVES do
    KNOWN[DIRECTIVES[i]] = true
end

local FLAGS = {
    ["upgrade-insecure-requests"] = true,
    ["block-all-mixed-content"]   = true,
}

local META_KEYS = {
    report_only     = true,
    ["report-only"] = true,
}

local function has_ngx()
    return type(ngx) == "table"
end

local function kebab(s)
    return (s:gsub("_", "-"))
end

local function snake(s)
    return (s:gsub("-", "_"))
end

local function b64_encode(bin)
    if has_ngx() and type(ngx.encode_base64) == "function" then
        local ok, res = pcall(ngx.encode_base64, bin)
        if ok and type(res) == "string" then
            return res
        end
    end

    do
        local ok, mime = pcall(require, "mime")
        if ok and mime and type(mime.b64) == "function" then
            return mime.b64(bin)
        end
    end

    local ABC = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
    local out = {}
    local n = #bin
    for i = 1, n, 3 do
        local a = bin:byte(i)
        local b = (i + 1 <= n) and bin:byte(i + 1) or 0
        local c = (i + 2 <= n) and bin:byte(i + 2) or 0
        local have = 1 + ((i + 1 <= n) and 1 or 0) + ((i + 2 <= n) and 1 or 0)
        local pack = a * 65536 + b * 256 + c

        local function idx(shift)
            return math.floor(pack / shift) % 64 + 1
        end

        local i1, i2, i3, i4 = idx(262144), idx(4096), idx(64), (pack % 64) + 1
        out[#out + 1] = ABC:sub(i1, i1)
        out[#out + 1] = ABC:sub(i2, i2)
        out[#out + 1] = (have >= 2) and ABC:sub(i3, i3) or "="
        out[#out + 1] = (have == 3) and ABC:sub(i4, i4) or "="
    end
    return table.concat(out)
end

local function random_bytes(n)
    if has_ngx() then
        local ok, rnd = pcall(require, "resty.random")
        if ok and rnd and type(rnd.bytes) == "function" then
            local buf = rnd.bytes(n, true)
            if type(buf) == "string" and #buf == n then
                return buf
            end
        end
    end

    local f = io.open("/dev/urandom", "rb")
    if not f then
        return nil, "no secure random source"
    end
    local buf = f:read(n)
    f:close()
    if type(buf) ~= "string" or #buf ~= n then
        return nil, "short read from /dev/urandom"
    end
    return buf
end

local function json_lib()
    local ok, j = pcall(require, "cjson.safe")
    if ok and j and j.decode then return j end
    ok, j = pcall(require, "cjson")
    if ok and j and j.decode then return j end
    return nil
end

local Policy = {}
Policy.__index = Policy

local function is_policy(obj)
    return type(obj) == "table" and getmetatable(obj) == Policy
end

function Policy:__tostring()
    return "CSP<" .. self:build() .. ">"
end

function Policy:_add(directive, ...)
    if not KNOWN[directive] then
        return nil, "unknown directive: " .. tostring(directive)
    end

    if FLAGS[directive] then
        self._dir[directive] = true
        return self
    end

    local argc = select("#", ...)
    if argc == 0 then
        return self
    end

    local list = self._dir[directive]
    if type(list) ~= "table" then
        list = {}
        self._dir[directive] = list
    end

    local seen = {}
    for i = 1, #list do
        seen[list[i]] = true
    end

    for i = 1, argc do
        local v = select(i, ...)
        if type(v) == "string" and v ~= "" and not seen[v] then
            list[#list + 1] = v
            seen[v] = true
        end
    end
    return self
end

for i = 1, #DIRECTIVES do
    local directive = DIRECTIVES[i]
    local method = snake(directive)
    Policy[method] = function(self, ...)
        local obj, err = self:_add(directive, ...)
        if not obj then error(err, 2) end
        return obj
    end
end

function Policy:set(directive, ...)
    if type(directive) ~= "string" or not KNOWN[directive] then
        error("unknown directive: " .. tostring(directive), 2)
    end
    self._dir[directive] = nil
    local obj, err = self:_add(directive, ...)
    if not obj then error(err, 2) end
    return obj
end

function Policy:remove(directive)
    if type(directive) == "string" then
        self._dir[directive] = nil
    end
    return self
end

function Policy:clear()
    self._dir = {}
    return self
end

function Policy:report_only(enabled)
    self._report_only = (enabled == nil) and true or not not enabled
    return self
end

function Policy:is_report_only()
    return self._report_only
end

function Policy:clone()
    local copy = _M.new()
    copy._report_only = self._report_only
    for k, v in pairs(self._dir) do
        if type(v) == "table" then
            local t = {}
            for i = 1, #v do t[i] = v[i] end
            copy._dir[k] = t
        else
            copy._dir[k] = v
        end
    end
    return copy
end

function Policy:merge(other)
    if not is_policy(other) then
        error("merge() expects a resty.csp policy", 2)
    end
    for directive, values in pairs(other._dir) do
        if type(values) == "table" then
            for i = 1, #values do
                local obj, err = self:_add(directive, values[i])
                if not obj then error(err, 2) end
            end
        else
            self._dir[directive] = values
        end
    end
    return self
end

function Policy:build()
    local parts = {}
    for i = 1, #DIRECTIVES do
        local d = DIRECTIVES[i]
        local v = self._dir[d]
        if v == true then
            parts[#parts + 1] = d
        elseif type(v) == "table" and #v > 0 then
            parts[#parts + 1] = d .. " " .. table.concat(v, " ")
        end
    end
    return table.concat(parts, "; ")
end

function Policy:header()
    local name = self._report_only
        and "Content-Security-Policy-Report-Only"
        or  "Content-Security-Policy"
    return name, self:build()
end

function Policy:apply()
    if not has_ngx() or type(ngx.header) ~= "table" then
        return nil, "apply() requires OpenResty (ngx.header)"
    end
    local name, value = self:header()
    if value ~= "" then
        ngx.header[name] = value
    end
    return self
end

function _M.new()
    return setmetatable({ _dir = {}, _report_only = false }, Policy)
end

function _M.nonce(value)
    if type(value) ~= "string" or value == "" then
        error("nonce() needs a non-empty string", 2)
    end
    if value:find("[%s'\"]") then
        error("nonce value must not contain whitespace or quotes", 2)
    end
    return "'nonce-" .. value .. "'"
end

function _M.generate_nonce(len)
    len = tonumber(len) or 16
    if len ~= math.floor(len) or len < 8 or len > 64 then
        return nil, "nonce length must be an integer in [8, 64]"
    end
    local raw, err = random_bytes(math.ceil(len * 3 / 4))
    if not raw then
        return nil, err
    end
    local encoded = b64_encode(raw):gsub("=", "")
    if #encoded < len then
        return nil, "insufficient entropy encoding"
    end
    return encoded:sub(1, len)
end

function _M.hash(algo, content)
    if type(algo) ~= "string" then
        return nil, "algorithm must be a string"
    end
    if type(content) ~= "string" then
        return nil, "content must be a string"
    end
    if algo ~= "sha256" and algo ~= "sha384" and algo ~= "sha512" then
        return nil, "unsupported algorithm (use sha256, sha384, sha512)"
    end

    local ok, sha = pcall(require, "resty." .. algo)
    if not ok or type(sha) ~= "table" or type(sha.new) ~= "function" then
        return nil, "resty." .. algo .. " is not available"
    end

    local h = sha:new()
    if not h then
        return nil, "hasher init failed"
    end
    h:update(content)
    local digest = h:final()
    if type(digest) ~= "string" or digest == "" then
        return nil, "digest failed"
    end
    return "'" .. algo .. "-" .. b64_encode(digest) .. "'"
end

function _M.from(config)
    if type(config) ~= "table" then
        return nil, "from() expects a table"
    end

    local policy = _M.new()

    local ro = config.report_only
    if ro == nil then ro = config["report-only"] end
    if ro ~= nil then
        policy:report_only(not not ro)
    end

    for key, values in pairs(config) do
        if not META_KEYS[key] then
            if type(key) ~= "string" then
                return nil, "directive keys must be strings"
            end
            local directive = kebab(key)
            if not KNOWN[directive] then
                return nil, "unknown directive in config: " .. key
            end

            if FLAGS[directive] then
                if values == true then
                    policy._dir[directive] = true
                elseif values ~= false and values ~= nil then
                    return nil, directive .. " is a flag (use true/false)"
                end
            elseif type(values) == "string" then
                if values == "" then
                    return nil, "empty value for " .. directive
                end
                local obj, err = policy:_add(directive, values)
                if not obj then return nil, err end
            elseif type(values) == "table" then
                for i = 1, #values do
                    local v = values[i]
                    if type(v) ~= "string" or v == "" then
                        return nil, "values for " .. directive .. " must be non-empty strings"
                    end
                    local obj, err = policy:_add(directive, v)
                    if not obj then return nil, err end
                end
            else
                return nil, "invalid value type for " .. directive
            end
        end
    end

    return policy
end

function _M.from_json(str)
    if type(str) ~= "string" or str == "" then
        return nil, "from_json() expects a non-empty string"
    end
    local j = json_lib()
    if not j then return nil, "cjson is not available" end
    local cfg, err = j.decode(str)
    if type(cfg) ~= "table" then
        return nil, err or "JSON root must be an object"
    end
    return _M.from(cfg)
end

function _M.from_file(path)
    if type(path) ~= "string" or path == "" then
        return nil, "from_file() expects a path"
    end
    local f, err = io.open(path, "r")
    if not f then
        return nil, "cannot open " .. path .. ": " .. tostring(err)
    end
    local body = f:read("*a")
    f:close()
    if type(body) ~= "string" or body == "" then
        return nil, "empty policy file"
    end
    return _M.from_json(body)
end

function _M.strict()
    return _M.new()
        :default_src(_M.NONE)
        :script_src(_M.SELF)
        :style_src(_M.SELF)
        :img_src(_M.SELF)
        :font_src(_M.SELF)
        :connect_src(_M.SELF)
        :object_src(_M.NONE)
        :base_uri(_M.SELF)
        :form_action(_M.SELF)
        :frame_ancestors(_M.NONE)
        :upgrade_insecure_requests()
end

function _M.basic()
    return _M.new()
        :default_src(_M.SELF)
        :script_src(_M.SELF)
        :style_src(_M.SELF, _M.UNSAFE_INLINE)
        :img_src(_M.SELF, _M.DATA)
        :font_src(_M.SELF)
        :connect_src(_M.SELF)
        :object_src(_M.NONE)
        :frame_ancestors(_M.SELF)
end

function _M.api()
    return _M.new()
        :default_src(_M.NONE)
        :frame_ancestors(_M.NONE)
        :base_uri(_M.NONE)
        :form_action(_M.NONE)
end

function _M.parse_report(body)
    if type(body) ~= "string" or body == "" then
        return nil, "empty body"
    end
    local j = json_lib()
    if not j then return nil, "cjson is not available" end
    local data, err = j.decode(body)
    if type(data) ~= "table" then
        return nil, err or "invalid JSON"
    end
    return data["csp-report"] or data
end

function _M.report_handler(callback)
    if callback ~= nil and type(callback) ~= "function" then
        error("callback must be a function or nil", 2)
    end
    return function()
        if not has_ngx() then
            error("report_handler requires OpenResty", 2)
        end
        ngx.req.read_body()
        local report, err = _M.parse_report(ngx.req.get_body_data() or "")
        if not report then
            ngx.status = 400
            ngx.say(err or "bad report")
            return ngx.exit(400)
        end
        if callback then
            local ok, cerr = pcall(callback, report)
            if not ok then
                ngx.log(ngx.ERR, "csp report callback: ", tostring(cerr))
            end
        end
        ngx.status = 204
        return ngx.exit(204)
    end
end

_M._DIRECTIVES = DIRECTIVES
_M._b64 = b64_encode

return _M
