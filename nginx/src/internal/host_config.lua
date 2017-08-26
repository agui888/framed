local api_config_shm = require "lib.api_config_shm"
if ngx.req.get_method() == "GET" then
    local path_info = api_config_shm.get(ngx.var.domain)
    local table_path_info = cjson.decode(path_info)
    ngx.say(return_data(0, "success", table_path_info))
elseif ngx.req.get_method() == "DELETE" then
    api_config_shm.delete(ngx.var.domain)
    ngx.say(return_data(0, "sucess"))
else
   ngx.say(return_data(1, "method is not allowed"))
end
