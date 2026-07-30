#!/usr/bin/env lua5.4

local ROOT = (arg[0]:match("(.*/)") or "./")
package.path = ROOT .. "../lib/?.lua;" .. package.path

local csp = require("resty.csp")

local passed, failed = 0, 0
local suite = "?"

local function pass()
    passed = passed + 1
end

local function fail(msg)
    failed = failed + 1
    io.stderr:write(("FAIL [%s] %s\n"):format(suite, msg))
end

local function ok(cond, msg)
    if cond then pass() else fail(msg or "assertion failed") end
end

local function eq(got, exp, msg)
    if got == exp then
        pass()
    else
        fail(("%s\n  got:      %q\n  expected: %q"):format(
            msg or "not equal", tostring(got), tostring(exp)))
    end
end

local function has(s, sub, msg)
    ok(type(s) == "string" and s:find(sub, 1, true) ~= nil,
        msg or ("missing %q in %q"):format(tostring(sub), tostring(s)))
end

local function test(name, fn)
    suite = name
    local fine, err = xpcall(fn, debug.traceback)
    if not fine then
        fail("error: " .. tostring(err))
    end
end

test("module", function()
    eq(csp._VERSION, "0.3.0")
    eq(csp.SELF, "'self'")
    eq(csp.NONE, "'none'")
end)

test("empty build", function()
    eq(csp.new():build(), "")
end)

test("fluent build order", function()
    local s = csp.new()
        :default_src(csp.SELF)
        :script_src(csp.SELF, "cdn.example.com")
        :upgrade_insecure_requests()
        :build()
    eq(s, "default-src 'self'; script-src 'self' cdn.example.com; upgrade-insecure-requests")
end)

test("dedupe", function()
    eq(csp.new():script_src(csp.SELF, "a"):script_src("a", "b"):build(),
       "script-src 'self' a b")
end)

test("set / remove / clear", function()
    local p = csp.new():script_src(csp.SELF, "a"):style_src(csp.SELF)
    eq(p:set("script-src", "b"):build(), "script-src b; style-src 'self'")
    p:remove("style-src")
    eq(p:build(), "script-src b")
    p:clear()
    eq(p:build(), "")
end)

test("clone + merge", function()
    local a = csp.new():script_src(csp.SELF)
    local b = a:clone():script_src("x")
    eq(a:build(), "script-src 'self'")
    eq(b:build(), "script-src 'self' x")
    eq(a:merge(csp.new():style_src(csp.SELF)):build(),
       "script-src 'self'; style-src 'self'")
end)

test("report-only header", function()
    local p = csp.new():default_src(csp.NONE):report_only()
    local name, value = p:header()
    eq(name, "Content-Security-Policy-Report-Only")
    eq(value, "default-src 'none'")
    ok(p:is_report_only())
end)

test("apply without ngx", function()
    local res, err = csp.api():apply()
    eq(res, nil)
    has(err, "OpenResty")
end)

test("apply with stub ngx", function()
    local store = {}
    _G.ngx = {
        header = setmetatable({}, {
            __newindex = function(_, k, v) store[k] = v end,
            __index = function(_, k) return store[k] end,
        }),
    }
    local p = csp.basic()
    ok(p:apply() == p)
    has(store["Content-Security-Policy"], "default-src 'self'")
    store = {}
    p:report_only(true):apply()
    ok(store["Content-Security-Policy-Report-Only"] ~= nil)
    _G.ngx = nil
end)

test("nonce helpers", function()
    eq(csp.nonce("abc"), "'nonce-abc'")
    ok(not pcall(csp.nonce, ""))
    ok(not pcall(csp.nonce, "bad value"))

    local n, err = csp.generate_nonce(16)
    ok(n ~= nil, err)
    eq(#n, 16)
    eq(csp.generate_nonce(3), nil)
end)

test("base64", function()
    eq(csp._b64("hello"), "aGVsbG8=")
end)

test("from()", function()
    local p, err = csp.from({
        default_src = { "'self'" },
        script_src = "'self'",
        upgrade_insecure_requests = true,
        report_only = true,
    })
    ok(p, err)
    ok(p:is_report_only())
    has(p:build(), "default-src 'self'")
    has(p:build(), "script-src 'self'")
    has(p:build(), "upgrade-insecure-requests")

    local bad, berr = csp.from({ defualt_src = { "'self'" } })
    eq(bad, nil)
    has(berr, "unknown directive")
end)

test("presets", function()
    has(csp.strict():build(), "object-src 'none'")
    has(csp.basic():build(), "'unsafe-inline'")
    has(csp.api():build(), "form-action 'none'")
end)

test("hash missing resty.sha", function()
    local h, err = csp.hash("sha256", "x")
    eq(h, nil)
    has(err, "not available")
end)

test("tostring", function()
    has(tostring(csp.new():default_src(csp.NONE)), "default-src 'none'")
end)

io.write(("\n%d passed, %d failed\n"):format(passed, failed))
os.exit(failed == 0 and 0 or 1)
