local _M = {};
local mt = { __index = _M }
local modelName = "acl_policy";
_G[modelName] = _M;

local rate_limit_shm = ngx.shared.rate_limit
local config = require "lib.config"
local util = require "lib.util"
local redis_limit_req_script_sha
local limit_result = {OK = 1, FORBIDDEN = 2}
--local redis_limit_req_script = [==[
--local key = KEYS[1]
--local rate = cjson.decode(KEYS[2])
--local keyname
--local block_keyname
--local expire
--
---- check block ip
--for unit, max_value in pairs(rate) do
--    if unit == "day" then
--        block_keyname = key .. "_day_block"
--    elseif unit == "hour" then
--        block_keyname = key .. "_hour_block"
--    elseif unit == "minute" then
--        block_keyname = key .. "_minute_block"
--    else
--        return {1}
--    end
--
--    local res, err = redis.pcall('EXISTS', block_keyname)
--    if type(res) == "table" and res.err then
--        return {err=res.err}
--    end
--    if tonumber(res) == 1 then
--        return {2}
--    end
--end
--
--for unit, max_value in pairs(rate) do
--    if unit == "day" then
--        expire = 24*60*60
--        keyname = key .. "_day"
--        block_keyname = key .. "_day_block"
--    elseif unit == "hour" then
--        expire = 60*60
--        keyname = key .. "_hour"
--        block_keyname = key .. "_hour_block"
--    elseif unit == "minute" then
--        expire = 60
--        keyname = key .. "_minute"
--        block_keyname = key .. "_minute_block"
--    else
--        return {1}
--    end
--
--    local res = redis.pcall('GET', keyname)
--    if type(res) == "table" and res.err then
--        return {err=res.err}
--    end
--
--    if res and tonumber(res) < max_value then
--       local res = redis.pcall('INCR', keyname)
--       if type(res) == "table" and res.err then
--           return {err=res.err}
--       end
--    elseif res and tonumber(res) >= max_value then
--        local res = redis.pcall('INCR', block_keyname)
--        if type(res) == "table" and res.err then
--            return {err=res.err}
--        end
--
--        local res = redis.pcall('EXPIRE', block_keyname, expire)
--        if type(res) == "table" and res.err then
--            return {err=res.err}
--        end
--        return {2}
--    else
--        local res = redis.pcall('INCR', keyname)
--        if type(res) == "table" and res.err then
--            return {err=res.err}
--        end
--
--        local res = redis.pcall('EXPIRE',keyname, expire)
--        if type(res) == "table" and res.err then
--            return {err=res.err}
--        end
--    end
--end
--
--return {1}
--]==]


function _M.new(self, redis_key, table_policy_id_config)
    if not table_policy_id_config then
        return
    end
    return setmetatable({redis_key = redis_key, table_policy_id_config = table_policy_id_config}, mt)
end


function _M.ip_black_limit(self)
    local ip_black_list
    if self.table_policy_id_config["ip_black_list_status"] == "true" or self.table_policy_id_config["ip_black_list_status"] == true then
        ip_black_list = self.table_policy_id_config["ip_black_list"]
        if not ip_black_list then
            return
        end
    else
        return
    end

    local remote_addr = ngx.var.remote_addr
    for k,v in pairs(ip_black_list) do
        if remote_addr == v or util.startswith(remote_addr, string.sub(v, 1, -5)) and util.endswith(v, "0/24") then
            return limit_result['FORBIDDEN']
        end
    end

    return limit_result["OK"]
end


function _M.ip_white_limit(self)
    local ip_white_list
    if self.table_policy_id_config["ip_white_list_status"] == "true" or self.table_policy_id_config["ip_white_list_status"] == true then
        ip_white_list = self.table_policy_id_config["ip_white_list"]
        if not ip_white_list then
            return
        end
    else
        return
    end

    local remote_addr = ngx.var.remote_addr
    for k,v in pairs(ip_white_list) do
        if remote_addr == v or util.startswith(remote_addr, string.sub(v, 1, -5)) and util.endswith(v, "0/24") then
            return limit_result['OK']
        end
    end

    return limit_result["FORBIDDEN"]
end


function _M.right_limit(self)
    local allow_method
    local right = self.table_policy_id_config["rw_rights"]
    if right == "r" then
        if util.check_method({"GET", "HEAD", "OPTIONS"}) then
            return limit_result["OK"]
        end
    elseif right == "rw" then
        return limit_result["OK"]
    end

    return limit_result["FORBIDDEN"]
end


function _M.referer_limit(self)
    local referer_risk
    local referer_lower
    local flag
    local referer_status = self.table_policy_id_config["referer_status"]
    if referer_status == true or referer_status == "true" then
        referer_risk = self.table_policy_id_config["referer_list"]
    else
        return
    end

    local referer = ngx.var.http_referer
    if referer ~= nil and #referer > 0 then
        referer_lower = string.lower(referer)
    else
        referer_lower = ""
    end

    if referer_risk ~= nil and next(referer_risk) ~= nil then
        for _,v in pairs(referer_risk) do
            local referer_str = string.lower(v)
            local reg_referer_risk = string.gsub(referer_str, "[.]", "%%.")
            reg_referer_risk = string.gsub(reg_referer_risk, "[*]", "%.%*")
            reg_referer_risk = string.gsub(reg_referer_risk, "[-]", "%%-")
            reg_referer_risk = string.gsub(reg_referer_risk, "[?]", "%%?")
            local m, err = string.match(referer_lower, reg_referer_risk)
            if m == nil then
                if err then
                    ngx.log(ngx.ERR, "referer match error: " .. err)
                end
            else
                flag = true
            end
        end
        if flag ~= true then
            return limit_result["FORBIDDEN"]
        end
    else
        return
    end

end


function _M.rate_limit(self)
    local rate
    if self.table_policy_id_config["rate_limit_per_period_status"] == "true" or self.table_policy_id_config["rate_limit_per_period_status"] == true then
        rate = self.table_policy_id_config["rate_limit_per_period"]
    else
        return
    end

    if rate == nil then
        return
    end

    for k, v in pairs(rate) do
        local key = self.redis_key .. "_" .. k .. "_block"
        local ok, flag = rate_limit_shm:get(key)
        if flag and type(flag) ~= "number" then
            ngx.log(ngx.ERR, "key " .. key .. " get failed:" .. flag)
            return
        end
        if ok ~= nil then
            if rate[k] > ok then
                rate_limit_shm:delete(key)
            else
                return limit_result["FORBIDDEN"]
            end
        end
    end

    ngx.ctx.rate = cjson.encode(rate)
    ngx.ctx.rate_limit_redis_key = self.redis_key
end


return _M;
