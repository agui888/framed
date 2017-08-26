local args = ngx.decode_args(ngx.var.args)
local request_uri = args["request_uri"]
if ngx.var.backend_type == 'a2a' then
    ngx.var.proxy_url = "http://api_prism" .. request_uri
elseif ngx.var.backend_type == 'd2a' then
    ngx.var.proxy_url = "http://api_crystal" .. request_uri
end
ngx.var.api_id = args["api_id"]
ngx.var.api_version = args["api_adapter_version"]
ngx.ctx.rate = args["rate"]
ngx.ctx.rate_limit_redis_key = args["rate_limit_redis_key"]
ngx.var.orignal_uri = ngx.var.uri
-- ngx.ctx.rate_vcode_white_list_flag = args["rate_vcode_white_list_flag"]
-- ngx.ctx.rate_vcode_black_list_flag = args["rate_vcode_black_list_flag"]
