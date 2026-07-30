LUA ?= lua5.4
DOCKER_IMAGE ?= openresty/openresty:alpine-fat

.PHONY: test test-resty test-nginx all

all: test test-resty

test:
	$(LUA) t/csp_test.lua

test-resty:
	docker run --rm -v "$(CURDIR):/src" -w /src $(DOCKER_IMAGE) \
		resty -I lib t/resty/01_apply.lua

test-nginx:
	prove -v t/csp.t
