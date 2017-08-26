local exit_code = require "lib.exit_code"
local api_config_shm = require "lib.api_config_shm"
local config = require "lib.config"
local util = require "lib.util"
local request_host = ngx.var.host
local remote_addr = ngx.var.remote_addr

local caller_id_encrypt = ngx.var.cookie_caller
local api_path_id_encrypt = ngx.var.cookie_apipath
local caller_id = util.decrypt(caller_id_encrypt)
local api_path_id = util.decrypt(api_path_id_encrypt)
local rate_hash_key = api_path_id .. "_" .. caller_id
if tonumber(caller_id) == 0 then
    rate_hash_key = api_path_id .. "_" .. caller_id .. "_" .. remote_addr
end

local check_result = util.check_sign_url("/baishancloud-juhe-captcha/create")
if check_result == nil then
    exit_code.err_exit("SignAuthFail")
end

local api_config_shm = api_config_shm:new(request_host)
local path_info = api_config_shm:get_path_info()
path_info = cjson.decode(path_info)
if path_info == nil or #path_info == 0 then
    exit_code.err_exit("PathInfoNotFound")
end

api_id = util.get_api_id(path_info)
if api_id == nil then
    exit_code.err_exit("ApiNotFound")
end

--设置随机种子
local resty_uuid = require("lua_uuid")
local millisecond = ngx.now()
local random_salt = string.sub(millisecond, 1, 10) .. string.sub(millisecond, 12, 14)
math.randomseed(random_salt)

--在32个备选字符中随机筛选4个作为captcha字符串
local dict = {'A','B','C','D','E','F','G','H','J','K','L','M','N','P','Q','R','S','T','U','V','W','X','Y','Z','2','3','4','5','6','7','8','9'}
local stringmark=""
for i=1,4 do
    stringmark = stringmark..dict[math.random(1,32)]
end

--图片基本info
--picgid
local filename = "a-"..resty_uuid()
--图片78x26
local xsize = 78
local ysize = 26
--字体大小
local wsize = 17.5
--干扰线(yes/no)
local line = "yes"

--加载模块
local gd = require('gd')
--创建面板
local im = gd.createTrueColor(xsize, ysize)
--定义颜色
local black = im:colorAllocate(0, 0, 0)
local grey = im:colorAllocate(202, 202, 202)
local color = {}
for c=1,100 do
    color[c] = im:colorAllocate(math.random(100), math.random(100), math.random(100))
end
--画背景
x, y = im:sizeXY()
im:filledRectangle(0, 0, x, y, grey)
--画字符
gd.useFontConfig(true)
for i=1,4 do
    k=(i-1)*16+3
    im:stringFT(color[math.random(100)], "Arial:bold", wsize,math.rad(math.random(-10,10)), k, 22, string.sub(stringmark,i,i))
end
--干扰线点
if line == "yes" then
    for j=1,math.random(3) do
        im:line(math.random(xsize), math.random(ysize), math.random(xsize), math.random(ysize), color[math.random(100)])
    end
    for p=1,20 do
        im:setPixel(math.random(xsize), math.random(ysize), color[math.random(100)])
    end

end
--流输出
local fp = im:pngStr(750)

--redis中添加picgid为key,string为value的记录
local acl_redis = config.get_conf("acl_redis")
local red = util.rate_redis_init(acl_redis, rate_hash_key)  

local captcha_value = stringmark .. ":" .. api_id
ok, err = red:set(filename, captcha_value)
if not ok then
    ngx.log(ngx.ERR, "failed to set : ", err)
    return
end
ok, err = red:expire(filename, 60)
if not ok then
    ngx.log(ngx.ERR, "failed to expire : ", err)
    return
end

local ok, err = red:set_keepalive(10000, 500)
if not ok then
    ngx.log("failed to set keepalive: ", err)
end

--response header中传参picgid
local cookie_table = string.format("bscname=%s; path=/baishancloud-juhe-captcha", filename)
ngx.header['Set-Cookie'] = cookie_table 
ngx.header.content_type = "text/plain"

--页面返回pic
ngx.say(fp)

--nginx退出
ngx.exit(200)
