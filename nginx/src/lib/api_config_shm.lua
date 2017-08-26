local _M = {};
local mt = { __index = _M }
local modelName = "api_config_shm";
_G[modelName] = _M;

local yunlian = ngx.shared.yunlian
local resty_lock = require "resty.lock"
local util = require "lib.util"
local config = require "lib.config"


function _M.new(self, host)
    if not host then
        return
    end
    return setmetatable({host = host}, mt)
end


function _M.get(key)
    local value, flag = yunlian:get(key)
    if flag and type(flag) ~= "number" then
        ngx.log(ngx.ERR, "key " .. key .. " get failed:" .. flag)
        return
    end
    return value, flag
end


function _M.set(key, value, expire, flag)
    if not expire then
        expire = 0
    end
    if not flag then
        flag = 0
    end
    local ok, err = yunlian:set(key, value, expire, flag)
    if not ok then
        ngx.log(ngx.ERR, "key " .. key .. " update shm failed: " .. err)
        return false
    end
	return true
end


function _M.delete(key)
    yunlian:delete(key)
end

function _M.api_config_query(uri, request_method, data)
    if request_method == 'GET' then
        local value, value_flag = _M.get(uri)
        if value_flag ~= 1 and value ~= nil then
            local table_res_body = cjson.decode(value)
            if table_res_body and table_res_body["projects"] and type(table_res_body["projects"]) == "table" then
                ngx.log(ngx.ERR, "cached: ", uri)
                return true, table_res_body["projects"]
            end
        end
    end
    local res = util.send_http(uri, request_method, data)
    local table_res_body = cjson.decode(res.body)
    if table_res_body and table_res_body["projects"] and type(table_res_body["projects"]) == "table" then
        if request_method == 'GET' then
            _M.set(uri, res.body, 10)
        end
        ngx.log(ngx.ERR, "cache miss: ", uri)
        return true, table_res_body["projects"]
    end
    return false, nil
end

function _M.api_config_http(uri, request_method, keyname)
    local value, value_flag = _M.get(keyname)
    if value_flag == 1 or value == nil then
        local lock = resty_lock:new("my_locks")
        local elapsed, err = lock:lock(keyname)
        if not elapsed then
            ngx.log(ngx.ERR, "failed to acquire the lock: ", err)
        end

        local res = util.send_http(uri, request_method, "key=" .. keyname)

        local ok, err = lock:unlock()
        if not ok then
            ngx.log(ngx.ERR, "failed to unlock: ", err)
        end

        local table_res_body = cjson.decode(res.body)
        if table_res_body["Code"] ~= 0 and table_res_body["Code"] ~= 1 then
            return
        end
        value = table_res_body["Value"]
        if string.len(value) == 0 then
            value = "{}"
        end
        _M.set(keyname, value, 86400)
    end

    return value
end


function _M.get_project_info(self)
    local ok, project_info = _M.api_config_query(config.get_conf('api_config_core_api') .. '?host=' .. self.host, "GET")
    return ok, project_info
end

function _M.get_path_info(self)
    local path_info = _M.api_config_http(config.get_conf('api_config_http_uri'), "POST", self.host)
    return path_info
end


function _M.get_swagger_config(self, api_path_id)
    local keyname = api_path_id .. "_apipathconfig"
    local config = _M.api_config_http(config.get_conf('api_config_http_uri'), "POST", keyname)
    return config
end


function _M.get_caller(self, api_path_id)
    local keyname = api_path_id .. "_apipath2callerid"
    local caller_id_list = _M.api_config_http(config.get_conf('api_config_http_uri'), "POST", keyname)
    return caller_id_list
end


function _M.get_caller_config(self, caller_id)
    local keyname = caller_id .. "_caller"
    local caller_config = _M.api_config_http(config.get_conf('api_config_http_uri'), "POST", keyname)
    return caller_config
end


function _M.get_policy_config(self, caller_id)
    local keyname = caller_id .. "_aclpolicy"
    local policy_id_config = _M.api_config_http(config.get_conf('api_config_http_uri'), "POST", keyname)
    return policy_id_config
end


function _M.get_rate_black_white_list(self, api_path_id)
    local keyname = api_path_id .. "_captcha"
    local rate_black_white_list = _M.api_config_http(config.get_conf('api_config_http_uri'), "POST", keyname)
    return rate_black_white_list
end


function _M.set_rate_shm_key(self, key, expire)
    _M.set(key, 1, expire)
end


function _M.get_rate_shm_key(self, key)
    local value = _M.get(key)
    return value
end


function _M.get_security_config(self, api_id)
    local keyname = api_id .. "_security"
    local security_config = _M.api_config_http(config.get_conf('api_config_http_uri'), "POST", keyname)
    return security_config
end


function _M.get_adapter_version(self, api_id)
    local keyname = api_id .. "_adapterversion"
    local adapter_version = _M.api_config_http(config.get_conf('api_config_http_uri'), "POST", keyname)
    return adapter_version
end


function _M.get_adapter_anon_acl_policy(self, api_path_id)
    local keyname = api_path_id .. "_adapteranonaclpolicy"
    local adapteranonaclpolicy = _M.api_config_http(config.get_conf('api_config_http_uri'), "POST", keyname)
    return adapteranonaclpolicy
end


function _M.get_ssl_info(self)
    local keyname = self.host .. "_ssl"
    local host_ssl_info =  _M.api_config_http(config.get_conf('api_config_http_uri'), "POST", keyname)
    return host_ssl_info
end


function _M.flush_expire()
    yunlian:flush_all()
end


function _M.flush_all()
    yunlian:flush_all()
    yunlian:flush_expired()
end

return _M;
