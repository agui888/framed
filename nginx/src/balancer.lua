function main()
    local balancer = require "ngx.balancer"
    local ip_list = ngx.ctx.ip_list
    local backend_ip = ip_list[1]["backend_ip"]
    local backend_port = ip_list[1]["backend_port"]
    table.remove(ngx.ctx.ip_list, 1)

    if not ngx.ctx.tries then
        ngx.ctx.tries = 0
    end
 
    if ngx.ctx.tries == 0 then
        ngx.var.yunlian_upstream_address = backend_ip .. ":" .. backend_port
    else
        ngx.var.yunlian_upstream_address = ngx.var.yunlian_upstream_address .. ", " .. backend_ip .. ":" .. backend_port
    end

    if ngx.ctx.tries < 1 and #ngx.ctx.ip_list > 0 then
        local ok, err = balancer.set_more_tries(1)
            if not ok then
            ngx.log(ngx.ERR, "failed to set more tries: ", err)
        elseif err then
            ngx.log(ngx.ERR, "set more tries: ", err)
        end
    end
    ngx.ctx.tries = ngx.ctx.tries + 1
    
    local state, code = balancer.get_last_failure()
    if state then
        ngx.log(ngx.ERR, "state: ", state, ", code: ", code)
    end
    
    local ok, err = balancer.set_current_peer(backend_ip, backend_port)
    if not ok then
        ngx.log(ngx.ERR, "failed to set the current peer: ", err)
        return ngx.exit(500)
    end
end

main()
