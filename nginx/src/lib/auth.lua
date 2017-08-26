local _M = {};
local modelName = "auth";
_G[modelName] = _M;

local config = require "lib.config"
local util = require "lib.util"


function _M.get_caller_id(api_config_shm, caller_id_list)
    local apikey
    local auth_mode
    local real_caller_id
    local anonymous_caller_id

    if ngx.var.arg_apikey then
        auth_mode = "apikey"
        apikey = ngx.var.arg_apikey
    elseif ngx.req.get_headers()["x-auth-apikey"] then
        auth_mode = "apikey"
        apikey = ngx.req.get_headers()["x-auth-apikey"]
    elseif ngx.var.remote_user then
        auth_mode = "basic"
    else
        auth_mode = "iplist"
    end

    for key, caller_id in pairs(caller_id_list) do
        local caller_id_config = api_config_shm:get_caller_config(caller_id)
        if not caller_id_config then
            return
        end
        local table_caller_id_config = cjson.decode(caller_id_config)

        if not table_caller_id_config then
            ngx.log(ngx.ERR, "caller id:" .. caller_id .. " ,config parse failed")
        else
            if auth_mode == table_caller_id_config["auth_mode"] then
                if auth_mode == "apikey" then
                    if apikey == table_caller_id_config["apikey"] then
                        real_caller_id = caller_id
                        break
                    end
                elseif auth_mode == "basic" then
                    if ngx.var.remote_user == table_caller_id_config["basic_auth_username"] and ngx.var.remote_passwd == table_caller_id_config["basic_auth_password"] then
                        real_caller_id = caller_id
                        break
                    end
                elseif auth_mode == "iplist" then
                    local remote_addr = ngx.var.remote_addr
                    for k, v in pairs(table_caller_id_config["ip_list"]) do
                        if remote_addr == v or util.startswith(remote_addr, string.sub(v, 1, -5)) and util.endswith(v, "0/24") then
                            real_caller_id = caller_id
                            break
                        end
                    end
                    if real_caller_id then
                        break
                    end
                end
            end
        end
    end

    return real_caller_id, auth_mode

end

function _M.auth_request(api_config_shm, api_path_id)
    -- auth
    local caller_id_list = api_config_shm:get_caller(api_path_id)
    local table_caller_id_list = cjson.decode(caller_id_list)
    if not table_caller_id_list then
        return
    end

    local caller_id, auth_mode = _M.get_caller_id(api_config_shm, table_caller_id_list)

    if caller_id == nil then
        if auth_mode == "basic" then
            ngx.header.www_authenticate = [[Basic realm="yunlian api gateway basic auth"]]
        end
        return
    end

    return caller_id

end



function _M.get_caller(callers)
    local apikey
    local request_auth_mode
    local real_caller

    if ngx.var.arg_apikey then
        request_auth_mode = "apikey"
        apikey = ngx.var.arg_apikey
    elseif ngx.req.get_headers()["x-auth-apikey"] then
        request_auth_mode = "apikey"
        apikey = ngx.req.get_headers()["x-auth-apikey"]
    elseif ngx.var.remote_user then
        request_auth_mode = "basic"
    else
        request_auth_mode = "anonymous"
    end

    for idx, caller in ipairs(callers) do
        if not caller then
            ngx.log(ngx.ERR, "caller:" .. caller .. ", parse failed")
        else
            if request_auth_mode == caller["auth_mode"] then
                if request_auth_mode == "apikey" then
                    if apikey == caller["apikey"] then
                        real_caller = caller
                        break
                    end
                elseif request_auth_mode == "basic" then
                    if ngx.var.remote_user == caller["basic_auth_username"] and ngx.var.remote_passwd == caller["basic_auth_password"] then
                        real_caller = caller
                        break
                    end
                elseif request_auth_mode == "anonymous" then
                    real_caller = caller
                    break
                end
            end
        end
    end

    return real_caller, request_auth_mode
end


function _M.auth_request_caller(callers)
    local caller, auth_mode = _M.get_caller(callers)
    if caller == nil then
        if auth_mode == "basic" then
            ngx.header.www_authenticate = [[Basic realm="yunlian api gateway basic auth"]]
        end
        return
    end
    return caller
end

return _M;
