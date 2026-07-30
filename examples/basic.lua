local csp = require("resty.csp")

csp.strict():apply()

csp.basic():apply()

csp.api():apply()
