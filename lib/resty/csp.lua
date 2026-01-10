local _M = {
    _VERSION = "0.1.0",
    
    SELF = "'self'",
    NONE = "'none'",
    UNSAFE_INLINE = "'unsafe-inline'",
    UNSAFE_EVAL = "'unsafe-eval'",
    STRICT_DYNAMIC = "'strict-dynamic'",
    WASM_UNSAFE_EVAL = "'wasm-unsafe-eval'",
    DATA = "data:",
    BLOB = "blob:",
    HTTPS = "https:",
}

local DIRECTIVES = {
    "default-src", "script-src", "script-src-elem", "script-src-attr",
    "style-src", "style-src-elem", "style-src-attr", "img-src", "font-src",
    "connect-src", "media-src", "object-src", "prefetch-src", "frame-src",
    "child-src", "worker-src", "manifest-src", "base-uri", "sandbox",
    "form-action", "frame-ancestors", "navigate-to", "report-uri", "report-to",
    "require-trusted-types-for", "trusted-types",
    "upgrade-insecure-requests", "block-all-mixed-content"
}

local NO_VALUE = {
    ["upgrade-insecure-requests"] = true,
    ["block-all-mixed-content"] = true
}

local function to_method_name(directive)
    return (directive:gsub("-", "_"))
end

local function is_valid_directive(name)
    for _, d in ipairs(DIRECTIVES) do
        if d == name then return true end
    end
    return false
end

local Policy = {}
Policy.__index = Policy

function Policy:__tostring()
    return string.format("CSP<%s>", self:build())
end

function _M.new()
    return setmetatable({ _directives = {}, _report_only = false }, Policy)
end

function Policy:_add(directive, ...)
    local values = {...}
    
    if NO_VALUE[directive] then
        self._directives[directive] = true
        return self
    end
    
    if #values == 0 then
        return self
    end
    
    self._directives[directive] = self._directives[directive] or {}
    local existing = self._directives[directive]
    local seen = {}
    for _, v in ipairs(existing) do
        seen[v] = true
    end
    
    for _, v in ipairs(values) do
        if type(v) == "string" and not seen[v] then
            existing[#existing + 1] = v
            seen[v] = true
        end
    end
    
    return self
end

for _, directive in ipairs(DIRECTIVES) do
    local method = to_method_name(directive)
    Policy[method] = function(self, ...)
        return self:_add(directive, ...)
    end
end

function Policy:set(directive, ...)
    if not is_valid_directive(directive) then
        error("unknown directive: " .. tostring(directive))
    end
    self._directives[directive] = nil
    return self:_add(directive, ...)
end

function Policy:remove(directive)
    self._directives[directive] = nil
    return self
end

function Policy:clear()
    self._directives = {}
    return self
end

function Policy:report_only(enabled)
    self._report_only = enabled ~= false
    return self
end

function Policy:clone()
    local copy = _M.new()
    copy._report_only = self._report_only
    for k, v in pairs(self._directives) do
        if type(v) == "table" then
            copy._directives[k] = {}
            for i, val in ipairs(v) do
                copy._directives[k][i] = val
            end
        else
            copy._directives[k] = v
        end
    end
    return copy
end

function Policy:merge(other)
    for directive, values in pairs(other._directives) do
        if type(values) == "table" then
            for _, v in ipairs(values) do
                self:_add(directive, v)
            end
        else
            self._directives[directive] = values
        end
    end
    return self
end

function Policy:build()
    local parts = {}
    
    for _, directive in ipairs(DIRECTIVES) do
        local values = self._directives[directive]
        if values == true then
            parts[#parts + 1] = directive
        elseif type(values) == "table" and #values > 0 then
            parts[#parts + 1] = directive .. " " .. table.concat(values, " ")
        end
    end
    
    return table.concat(parts, "; ")
end

function Policy:header()
    local name = self._report_only 
        and "Content-Security-Policy-Report-Only"
        or "Content-Security-Policy"
    return name, self:build()
end

function Policy:apply()
    if not ngx or not ngx.header then
        error("apply() requires OpenResty ngx environment")
    end
    local name, value = self:header()
    if value ~= "" then
        ngx.header[name] = value
    end
    return self
end

function _M.nonce(value)
    if type(value) ~= "string" or value == "" then
        error("nonce() requires a non-empty string")
    end
    return "'nonce-" .. value .. "'"
end

function _M.hash(algo, content)
    if type(algo) ~= "string" then
        return nil, "algorithm must be a string"
    end
    if type(content) ~= "string" then
        return nil, "content must be a string"
    end
    
    local supported = { sha256 = true, sha384 = true, sha512 = true }
    if not supported[algo] then
        return nil, "unsupported algorithm: " .. algo .. " (use sha256, sha384, sha512)"
    end
    
    local ok, sha = pcall(require, "resty." .. algo)
    if not ok then
        return nil, "resty." .. algo .. " not available"
    end
    
    local h = sha:new()
    if not h then
        return nil, "failed to create hasher"
    end
    
    h:update(content)
    local digest = h:final()
    if not digest then
        return nil, "failed to compute digest"
    end
    
    return "'" .. algo .. "-" .. ngx.encode_base64(digest) .. "'"
end

function _M.generate_nonce(len)
    len = len or 16
    
    local ok, rnd = pcall(require, "resty.random")
    if ok and rnd.bytes then
        local b = rnd.bytes(len, true)
        if b then return ngx.encode_base64(b):sub(1, len) end
    end
    
    local f = io.open("/dev/urandom", "rb")
    if f then
        local b = f:read(len)
        f:close()
        if b then return ngx.encode_base64(b):sub(1, len) end
    end
    
    math.randomseed(ngx and (ngx.now() * 1e6) or (os.time() * 1000))
    local c = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
    local r = {}
    for i = 1, len do
        local idx = math.random(#c)
        r[i] = c:sub(idx, idx)
    end
    return table.concat(r)
end

function _M.from(config)
    local policy = _M.new()
    
    for key, values in pairs(config) do
        local directive = key:gsub("_", "-")
        
        if type(values) == "table" then
            for _, v in ipairs(values) do
                policy:_add(directive, v)
            end
        elseif type(values) == "string" then
            policy:_add(directive, values)
        elseif values == true and NO_VALUE[directive] then
            policy._directives[directive] = true
        end
    end
    
    return policy
end

function _M.from_json(str)
    local ok, json = pcall(require, "cjson.safe")
    if not ok then
        ok, json = pcall(require, "cjson")
    end
    if not ok then
        return nil, "cjson not available"
    end
    
    local config, err = json.decode(str)
    if not config then
        return nil, err
    end
    
    return _M.from(config)
end

function _M.from_file(path)
    local f, err = io.open(path, "r")
    if not f then
        return nil, "cannot open file: " .. tostring(err)
    end
    
    local content = f:read("*a")
    f:close()
    
    return _M.from_json(content)
end

function _M.strict()
    return _M.new()
        :default_src(_M.NONE)
        :script_src(_M.SELF)
        :style_src(_M.SELF)
        :img_src(_M.SELF)
        :font_src(_M.SELF)
        :connect_src(_M.SELF)
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
end

function _M.api()
    return _M.new()
        :default_src(_M.NONE)
        :frame_ancestors(_M.NONE)
end

function _M.parse_report(body)
    if not body or body == "" then
        return nil, "empty body"
    end
    
    local ok, json = pcall(require, "cjson.safe")
    if not ok then
        ok, json = pcall(require, "cjson")
    end
    if not ok then
        return nil, "cjson not available"
    end
    
    local data, err = json.decode(body)
    if not data then
        return nil, err
    end
    
    return data["csp-report"] or data
end

function _M.report_handler(callback)
    return function()
        ngx.req.read_body()
        local report, err = _M.parse_report(ngx.req.get_body_data())
        
        if not report then
            ngx.status = 400
            return ngx.exit(400)
        end
        
        if callback then
            pcall(callback, report)
        end
        
        ngx.status = 204
        ngx.exit(204)
    end
end

return _M
