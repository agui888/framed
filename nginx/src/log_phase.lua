local config = require "lib.config"
local redis_limit_req_script_sha
local limit_result = {OK = 1, FORBIDDEN = 2}

local redis_limit_req_script = [==[
local key = KEYS[1]
local rate = cjson.decode(KEYS[2])
local keyname
local block_keyname
local expire

-- check block ip
for unit, max_value in pairs(rate) do
    if unit == "day" then
        block_keyname = key .. "_day_block"
    elseif unit == "hour" then
        block_keyname = key .. "_hour_block"
    elseif unit == "minute" then
        block_keyname = key .. "_minute_block"
    else
        return {1}
    end
end

for unit, max_value in pairs(rate) do
    if unit == "day" then
        expire = 24*60*60
        keyname = key .. "_day"
        block_keyname = key .. "_day_block"
    elseif unit == "hour" then
        expire = 60*60
        keyname = key .. "_hour"
        block_keyname = key .. "_hour_block"
    elseif unit == "minute" then
        expire = 60
        keyname = key .. "_minute"
        block_keyname = key .. "_minute_block"
    else
        return {1}
    end

    local res = redis.pcall('INCR', keyname)
    if type(res) == "table" and res.err then
        return {err=res.err}
    end

    if tonumber(res) == 1 then
        local res = redis.pcall('EXPIRE', keyname, expire)
        if type(res) == "table" and res.err then
            return {err=res.err}
        end
    end

    if res and tonumber(res) > max_value-1 then
        local res = redis.pcall('INCR', block_keyname)
        if type(res) == "table" and res.err then
            return {err=res.err}
        end

        local res = redis.pcall('EXPIRE', block_keyname, expire)
        if type(res) == "table" and res.err then
            return {err=res.err}
        end
        return {2, block_keyname, expire, max_value}
    end
end

return {1}
]==]


local rate = ngx.ctx.rate
local redis_key = ngx.ctx.rate_limit_redis_key
local rate_vcode_white_list_flag = ngx.ctx.rate_vcode_white_list_flag
local rate_vcode_black_list_flag = ngx.ctx.rate_vcode_black_list_flag
local rate_limit_shm = ngx.shared.rate_limit

function rate_limit()
    local acl_redis = config.get_conf("acl_redis")
    local acl_redis_len = #acl_redis
    local get_redis_num = ngx.crc32_short(redis_key) % acl_redis_len
    get_redis_num = get_redis_num + 1

    local redis = require "resty.redis"
    local red = redis:new()
    red:set_timeout(5000) -- 1 sec

    local ok, err = red:connect(acl_redis[get_redis_num]["ip"], acl_redis[get_redis_num]['port'])
    if not ok then
        for i=1, acl_redis_len do
            if i ~= get_redis_num then
                ok, err = red:connect(acl_redis[i]["ip"], acl_redis[i]['port'])
                if ok then
                    break
                end
            end
        end

        if not ok then
            ngx.log(ngx.ERR, "failed to connect redis: " .. err)
            return
        end
    end

    if not redis_limit_req_script_sha then
        local res, err = red:script("LOAD", redis_limit_req_script)
        if not res then
            ngx.log(ngx.ERR, err)
            return
        end
        ngx.log(ngx.NOTICE, "load redis limit req script")
        redis_limit_req_script_sha = res
    end

    local res, err = red:evalsha(redis_limit_req_script_sha, 2, redis_key, rate)
    if not res then
        redis_limit_req_script_sha = nil
        ngx.log(ngx.ERR, "redis script exec failed: " .. err)
        return
    end

    local ok, err = red:set_keepalive(30000, 10000)
    if not ok then
        ngx.log(ngx.ERR, "redis failed to set keepalive: ", err)
        return
    end

    if res[1] == limit_result["FORBIDDEN"] then
        local keyname = res[2]
        local expire = res[3]
        local max_value = res[4]
        local ok, err = rate_limit_shm:set(keyname, max_value, expire)
        if not ok then
            ngx.log(ngx.ERR, "key " .. key .. " update rate_limit shm failed: " .. err)
        end
    end

end

if rate ~= nil and redis_key ~= nil then
    ngx.timer.at(0, rate_limit)
end

-- if rate ~= nil and redis_key ~= nil and rate_vcode_white_list_flag ~= true and rate_vcode_black_list_flag ~= true then
--     ngx.timer.at(0, rate_limit)
-- end
