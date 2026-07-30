local csp = require("resty.csp")

csp.report_handler(function(report)
    ngx.log(ngx.WARN, "csp violated: ",
        tostring(report["violated-directive"]),
        " blocked: ",
        tostring(report["blocked-uri"]))
end)()
