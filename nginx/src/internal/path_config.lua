local key
local api_config_shm = require "lib.api_config_shm"
if ngx.req.get_method() == "GET" then

    if ngx.var.config_name == "swagger" then
        local swagger_config = api_config_shm.get(ngx.var.api_path_id .. "_apipathconfig")
        local table_swagger_config = cjson.decode(swagger_config)
        ngx.say(return_data(0, "success", table_swagger_config))
    elseif ngx.var.config_name == "caller" then
        local callers_config = {}
        local caller_ids = api_config_shm.get(ngx.var.api_path_id .. "_apipath2callerid")
        local table_caller_ids = cjson.decode(caller_ids)
        if table_caller_ids ~= nil then
            for _,v in pairs(table_caller_ids) do
                local tmp_table = {}
                local caller_config = api_config_shm.get(v .. "_caller")
                tmp_table["caller_id"] = v
                tmp_table["caller_config"] = caller_config or {}
                table.insert(callers_config, tmp_table)
            end
            ngx.say(return_data(0, "success", callers_config))
        else
            ngx.say(return_data(0, "api path id: " .. ngx.var.api_path_id .. ", nginx shm no corresponding caller config"))
        end
    elseif ngx.var.config_name == "policy" then
        local policys_config = {}
        local caller_ids = api_config_shm.get(ngx.var.api_path_id .. "_apipath2callerid")
        local table_caller_ids = cjson.decode(caller_ids)
        if table_caller_ids ~= nil then
            for _,v in pairs(table_caller_ids) do
                local tmp_table = {}
                local caller_config = api_config_shm.get(v .. "_aclpolicy")
                tmp_table["caller_id"] = v
                tmp_table["policy_config"] = caller_config or {}
                table.insert(policys_config, tmp_table)
            end
            ngx.say(return_data(0, "success", policys_config))
        else
            ngx.say(return_data(0, "api path id: " .. ngx.var.api_path_id .. ", nginx shm no corresponding policy config"))
        end
    end

elseif ngx.req.get_method() == "DELETE" then

    if ngx.var.config_name == "swagger" then
        api_config_shm.delete(ngx.var.api_path_id .. "_apipathconfig")
    elseif ngx.var.config_name == "caller" or ngx.var.config_name == "policy" then
        api_config_shm.delete(ngx.var.api_path_id .. "_apipath2callerid")
    end

end
