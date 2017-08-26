local config = require "lib.config"
local util = require "lib.util"
local exit_code = require "lib.exit_code"
local api_config_shm = require "lib.api_config_shm"
local redis = require "resty.redis"
local rate_limit_shm = ngx.shared.rate_limit
local remote_addr = ngx.var.remote_addr 

local check_result = util.check_sign_url("/baishancloud-juhe-captcha/check")
if check_result == nil then
    exit_code.err_exit("SignAuthFail") 
end

ngx.req.read_body()
local arg = ngx.req.get_post_args()
local input_captcha = arg["vcode"]
if input_captcha == nil or #input_captcha < 1 then
    ngx.exit(200)
end
local filename = ngx.var.cookie_bscname
local caller_id_encrypt = ngx.var.cookie_caller
local api_path_id_encrypt = ngx.var.cookie_apipath
local caller_id = util.decrypt(caller_id_encrypt)
local api_path_id = util.decrypt(api_path_id_encrypt)
local rate_white_black_url = config.get_conf("rate_white_black_url")
local filename_check_num = filename .. "_check_num"

local rate_hash_key = api_path_id .. "_" .. caller_id
if tonumber(caller_id) == 0 then
    rate_hash_key = api_path_id .. "_" .. caller_id .. "_" .. remote_addr
end

local acl_redis = config.get_conf("acl_redis")
local red = util.rate_redis_init(acl_redis, rate_hash_key)
if not red then
    local msg_table = {errno = 0, error = ""}
    ngx.say(cjson.encode(msg_table))
    ngx.exit(200)
end
local res1, err1 = red:exists(filename_check_num)
if not res1 then
    ngx.log(ngx.ERR, "failed to exists: " ..  err1)
    return
end
if res1 == 0 then
    local res3, err3 = red:expire(filename_check_num, 60)
    if not res3 then
        ngx.log(ngx.ERR, "failed to incr: " .. err3)
        return
    end
end
local res2, err2 = red:incr(filename_check_num)
if not res2 then
    ngx.log("failed to incr: " .. err2)
    return
end


local res, err = red:get(filename)
if not res then
    ngx.log(ngx.ERR, "failed to get: " .. err)
    return
end

if res == nil or res == ngx.null then
    local msg_table = {errno = 1, error = "验证码已过期"}
    ngx.say(cjson.encode(msg_table))
    ngx.exit(200)
end
local right_captcha = string.sub(res, 1, 4)
local api_id = string.sub(res, 6)

local security_config = api_config_shm:get_security_config(api_id)
local security_config_table = cjson.decode(security_config)
local vcode_max_incorrect_number = security_config_table["vcode_max_incorrect_number"]

if res2 > vcode_max_incorrect_number then
    local vcode_black_expired_s = security_config_table["vcode_black_expired_s"]
    local rate_black_key_shm = rate_hash_key .. "_rate_black"
    if vcode_black_expired_s > 0 and vcode_black_expired_s <= 3 then
        api_config_shm:set_rate_shm_key(rate_black_key_shm, vcode_black_expired_s)
    elseif vcode_black_expired_s > 3 then
        api_config_shm:set_rate_shm_key(rate_black_key_shm, 3)
    end
    util.delete_all_rate_keys(red, rate_hash_key)

    local body_data_table = { type = "black", ip = remote_addr, expired_time = ngx.time() + vcode_black_expired_s, api_path_id = api_path_id, caller_id = caller_id }
    local body_data_json = cjson.encode(body_data_table)
    util.send_http(rate_white_black_url, "POST", body_data_json, { ["Content-Type"] = "application/json" })
    exit_code.err_exit("RemoteAddrInVcodeBlackList")
end

if string.lower(right_captcha) == string.lower(input_captcha) then
    local rate_white_key_shm = rate_hash_key .. "_rate_white"
    local vcode_white_expired_s = security_config_table["vcode_white_expired_s"] 
    if vcode_white_expired_s > 0 and vcode_white_expired_s <= 3 then
        api_config_shm:set_rate_shm_key(rate_white_key_shm, vcode_white_expired_s)
    elseif vcode_white_expired_s > 3 then
        api_config_shm:set_rate_shm_key(rate_white_key_shm, 3)
    end

    util.delete_all_rate_keys(red, rate_hash_key)

    local body_data_table = { type = "white", ip = remote_addr, expired_time = ngx.time() + vcode_white_expired_s, api_path_id = api_path_id, caller_id = caller_id }
    local body_data_json = cjson.encode(body_data_table)
    util.send_http(rate_white_black_url, "POST", body_data_json, { ["Content-Type"] = "application/json" })
    ngx.header.content_type="text/html"
    local msg_table = {errno = 0, error = ""}
    ngx.say(cjson.encode(msg_table))
else
    ngx.header.content_type="text/html"
    local msg_table = {errno = 1, error = "验证码错误"}
    ngx.say(cjson.encode(msg_table))
end

local ok, err = red:set_keepalive(10000, 500)
if not ok then
    ngx.log("failed to set keepalive: ", err)
end
