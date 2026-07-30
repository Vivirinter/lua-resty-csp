use Test::Nginx::Socket::Lua;
use Cwd qw(cwd);

repeat_each(1);
plan tests => repeat_each() * blocks() * 2;

our $pwd = cwd();
our $HttpConfig = qq{
    lua_package_path "$pwd/lib/?.lua;;";
};

no_long_string();
run_tests();

__DATA__

=== TEST 1: strict preset sets CSP header
--- http_config eval: $::HttpConfig
--- config
    location /t {
        content_by_lua_block {
            local csp = require("resty.csp")
            assert(csp.strict():apply())
            ngx.say("ok")
        }
    }
--- request
GET /t
--- response_headers_like
Content-Security-Policy: default-src 'none';.*object-src 'none'
--- response_body
ok

=== TEST 2: nonce policy
--- http_config eval: $::HttpConfig
--- config
    location /t {
        content_by_lua_block {
            local csp = require("resty.csp")
            local nonce = assert(csp.generate_nonce())
            assert(csp.new()
                :script_src(csp.nonce(nonce))
                :object_src(csp.NONE)
                :apply())
            ngx.say(nonce)
        }
    }
--- request
GET /t
--- response_headers_like
Content-Security-Policy: script-src 'nonce-[A-Za-z0-9+/]+'; object-src 'none'
--- response_body_like
^[A-Za-z0-9+/]{8,}$

=== TEST 3: report-only mode
--- http_config eval: $::HttpConfig
--- config
    location /t {
        content_by_lua_block {
            local csp = require("resty.csp")
            assert(csp.api():report_only(true):apply())
            ngx.say("ok")
        }
    }
--- request
GET /t
--- response_headers_like
Content-Security-Policy-Report-Only: default-src 'none'
--- response_body
ok
