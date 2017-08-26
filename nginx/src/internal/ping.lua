--ping api
local api_config_shm = require "lib.api_config_shm"
function main()
    if ngx.req.get_method() ~= "POST"  then
        ngx.say(return_data(1, "please use the post method"))
        return
    end

    ngx.req.read_body()
    local table_data = ngx.req.get_post_args()
    local data = ngx.req.get_body_data()
    local key = table_data.key

    local value, flag = api_config_shm.get(key)
    if not value then
        ngx.say(return_data(0, "key " .. key .. " is not exist"))
        return
    elseif flag == 1  then
        ngx.say(return_data(0, "success"))
        return
    end

    local result = api_config_shm.set(key, value, 86400, 1)
    if result then
        ngx.say(return_data(0, "success!"))
    else
        ngx.say(return_data(1, "key " .. key .. " update shm failed"))
    end
end

main()
