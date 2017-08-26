local api_config_shm = require "lib.api_config_shm"
function main()
    if ngx.req.get_method() == "POST" then
        if ngx.var.action == "expire" then
            api_config_shm.flush_expire()
            ngx.say(return_data(0, "all keys have been marked as expired"))
        elseif ngx.var.action == "flush" then
            api_config_shm.flush_all()
            ngx.say(return_data(0, "all keys have been deleted"))
        end
    else
        ngx.say(return_data(1, "please use the post method"))
    end
end

main()
