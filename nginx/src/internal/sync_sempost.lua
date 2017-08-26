local util = require "lib.util"
local request_token = ngx.var.arg_request_token
local body_data = util.get_request_body()

local sync = ngx.shared.sync
local ok, err = sync:set(request_token, body_data, 10)
if not ok then
    ngx.log(ngx.ERR, "key " .. request_token .. " update shm failed: " .. err)
    ngx.say(return_data(1, err))
end

ngx.say(return_data(0, "success"))
