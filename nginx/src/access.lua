local util = require "lib.util"
local config = require "lib.config"
local api_config_shm = require "lib.api_config_shm"
local ws_buffer = ngx.shared.websocket_buffer
local auth = require "lib.auth"
local acl_policy = require "lib.acl_policy"
local exit_code = require "lib.exit_code"
-- local uuid = require "lua_uuid"
local request_uri = ngx.var.request_uri
local request_host = ngx.var.host
local original_uri = ngx.var.uri
local req_headers = ngx.req.get_headers()
local remote_addr = ngx.var.remote_addr
ngx.var.orignal_uri = original_uri



--sync block
function sync_handle(api_path_id, backend, wait_timeout, request_token)
    local notify_nginx_url = config.get_conf('notify_nginx_url') .. "?request_token=" .. request_token
    local sync = ngx.shared.sync
    local body_data = {}
    local taskqueue_url = config.get_conf('taskqueue_url')

    local request_header = req_headers
    request_header['host'] = ngx.var.backend_host
    local request_body = util.get_request_body()

    body_data['backend_url'] = backend
    body_data['notify_nginx_url'] = notify_nginx_url
    body_data['request_header'] = request_header
    body_data['request_body_b64'] = ngx.encode_base64(request_body)
    body_data['client_ip'] = remote_addr
    body_data['api_path_id'] = api_path_id
    local body_data_json = cjson.encode(body_data)

    if not wait_timeout then
        wait_timeout = 10
    end
    local sync_sleep_time_s = config.get_conf("sync_sleep_time_s")
    if not sync_sleep_time_s then
        sync_sleep_time_s = 0.1
    elseif tonumber(sync_sleep_time_s) > 1 then
        sync_sleep_time_s = 1
    end

    local taskqueue_res = util.send_http(taskqueue_url, "POST", body_data_json, { ["Content-Type"] = "application/json" })

    local loop_num = wait_timeout/sync_sleep_time_s
    for i=1, loop_num do
        local ok = sync:get(request_token)
        if ok then
            local taskqueue_res_data = cjson.decode(ok)
            local taskqueue_res_code = taskqueue_res_data["response_code"]
            if taskqueue_res_code == -1 then
                exit_code.err_exit("HalfAsyncResponseCodeError")
            end

            local response_header = taskqueue_res_data["response_header"]
            for k, v in pairs(response_header) do
                ngx.header[k] = v
            end

            local response_body_b64 = taskqueue_res_data["response_body_b64"]
            local response_body
            if response_body_b64 ~= nil then
                response_body = ngx.decode_base64(response_body_b64)
            end

            local ok, err = sync:delete(request_token)
            ngx.status = taskqueue_res_code
            ngx.say(response_body)
            ngx.exit(taskqueue_res_code)
        else
            ngx.sleep(0.1)
        end
    end

    exit_code.err_exit("HalfAsyncResponseTimeout")
end

--async non block
function async_handle(api_path_id, backend)
    local body_data = {}
    local taskqueue_url = config.get_conf('taskqueue_url')

    local request_header = req_headers
    request_header['host'] = ngx.var.backend_host
    local request_body = util.get_request_body()

    body_data['backend_url'] = backend
    body_data['request_header'] = request_header
    body_data['request_body_b64'] = ngx.encode_base64(request_body)
    body_data['client_ip'] = remote_addr
    body_data['api_path_id'] = api_path_id
    local body_data_json = cjson.encode(body_data)

    local taskqueue_res = util.send_http(taskqueue_url, "POST", body_data_json, { ["Content-Type"] = "application/json" })
    ngx.header["content_type"] = "application/json"
    ngx.say(return_data(0, "success"))
    ngx.exit(ngx.HTTP_OK)
end


--websocket
function websocket_receive(wb, api_path_id, request_token, backend)
    local notify_nginx_url = config.get_conf('notify_nginx_url') .. "?request_token=" .. request_token
    local body_data = {}
    local websocket_url = config.get_conf('websocket_url')

    local request_header = req_headers
    request_header['host'] = ngx.var.backend_host

    body_data['backend_url'] = backend
    body_data['request_header'] = request_header
    body_data['api_path_id'] = api_path_id
    body_data['notify_nginx_url'] = notify_nginx_url
    local body_data_json = cjson.encode(body_data)
    local taskqueue_res = util.send_http(websocket_url, "POST", body_data_json, { ["Content-Type"] = "application/json" })

    local ws_receive_sleep_time_s = config.get_conf("ws_receive_sleep_time_s")
    if not ws_receive_sleep_time_s then
        ws_receive_sleep_time_s = 0.1
    end

    wb:set_timeout(86400000)  -- change the network timeout to 1 second
    while true do
        local data, typ, err = wb:recv_frame()
        if not data then
            if not util.endswith(err, ": timeout") then
                ws_buffer:delete(request_token)
                local err = err or ""
                exit_code.err_exit("WebSocketReceiveError", "failed to receive a frame: " .. err)
            end
        end
        if typ == "close" then
            ws_buffer:delete(request_token)
            local bytes, err = wb:send_close(1000, "client disconnection request have been received, server had disconnection link")
            if not bytes then
                local err = err or ""
                exit_code.err_exit("WebSocketPassiveCloseFail", "failed to send the close frame: " .. err)
            end
            local code = err
            ngx.log(ngx.ERR, "server passive closing with status code ", code, " and message ", data)
            return
        end

        if typ == "ping" then
            local bytes, err = wb:send_pong(data)
            if not bytes then
                ws_buffer:delete(request_token)
                local err = err or ""
                exit_code.err_exit("WebSocketSendFail", "failed to send pong: " .. err)
            end
        elseif typ == "pong" then

        elseif data then
            local taskqueue_res = util.send_http(backend, "POST", data, {["Host"] = ngx.var.backend_host })
        end
        ngx.sleep(ws_receive_sleep_time_s)
    end
end


function websocket_send(wb, request_token)
    local request_url = request_host .. request_uri
    wb:set_timeout(500)  -- change the network timeout to 0.5 second
    local ok, err = ws_buffer:set(request_token, request_url)

    local ws_send_sleep_time_s = config.get_conf("ws_send_sleep_time_s")
    if not ws_send_sleep_time_s then
        ws_send_sleep_time_s = 1
    end

    local flag_key = request_token .. "_flag"
    while true do
        local ok = ws_buffer:get(flag_key)
        if ok == "new" then
            local data, err = ws_buffer:get(request_url)
            local set_result = ws_buffer:set(flag_key, 1, 120)
            if data then
                local bytes, err = wb:send_text(data)
                ws_buffer:incr(request_url .. "_request_token_incr", 1)
                if not bytes then
                    if not util.endswith(err, ": timeout") then
                        ws_buffer:delete(request_token)
                        local err = err or ""
                        exit_code.err_exit("WebSocketSendFail", "failed to send a text frame: " .. err)
                    end
                end
            end
        elseif ok == "close" then
            ws_buffer:delete(request_token)
            local bytes, err = wb:send_close(1000, "client authentication failed")
            if not bytes then
                local err = err or ""
                exit_code.err_exit("WebSocketActiveClose", "failed to send the close frame: " .. err)
            end
            local code = err
            ngx.log(ngx.ERR, "server active closing with status code ", code, " and message ", data)
            ngx.sleep(1)
            local data, typ, err = wb:recv_frame()
            if typ ~= "close" then
                exit_code.err_exit("WebSocketActiveClose")
            end

            return
        end
        ngx.sleep(ws_send_sleep_time_s)
    end
end

function main2()
    local api_config_shm = api_config_shm:new(request_host)
    local ok, project_info = api_config_shm:get_project_info()
    if not ok then
        exit_code.err_exit("PathInfoNotFound")
    end
    local router = require "lib.router"
    local router = require 'router'
    local r = router.new()
    for base_path, project in pairs(project_info) do
        if project["apis"] ~= nil then
            for path, path_info in pairs(project["apis"]) do
                if path_info["methods"] ~= nil then
                    for method, method_info in pairs(path_info["methods"]) do
                        local full_path, prefix_path, suffix_path
                        if string.len(base_path) == 0 then
                            prefix_path = ''
                        elseif base_path == '/' then
                            prefix_path = ''
                        else
                            prefix_path = base_path
                            if not util.startswith(base_path, "/") then
                                prefix_path = '/' .. base_path
                            end
                            if util.endswith(prefix_path, "/") then
                                prefix_path = string.sub(prefix_path, 1, string.len(prefix_path) - 1)
                            end
                        end
                        if string.len(path) == 0 then
                            suffix_path = '/'
                        elseif path == '/' then
                            suffix_path = '/'
                        elseif not util.startswith(path, "/") then
                            suffix_path = '/' .. path
                        else
                            suffix_path = path
                        end
                        full_path = prefix_path .. suffix_path
                        r:match(string.upper(method), full_path, function(params)
                            if method_info['status'] ~= "on" then
                                exit_code.err_exit("ApiPathStatusOff")
                            end
                            -- API ID
                            ngx.var.api_path_id = method_info['api_info_id']
                            ngx.var.backend_type = method_info['backend_type']
                            -- Project ID
                            ngx.var.api_id = project['project_id']
                            local caller = auth.auth_request_caller(project['callers'])
                            if caller == nil then
                                exit_code.err_exit("AuthFail")
                            else
                                if caller['auth_mode'] == 'anonymous' then
                                    ngx.var.caller_id = 0
                                else
                                    ngx.var.caller_id = caller['caller_id']
                                end
                                -- local args = {request_uri = request_uri, api_id = project['project_id'], api_adapter_version = project['project_version'], rate = ngx.ctx.rate, rate_limit_redis_key = ngx.ctx.rate_limit_redis_key, rate_vcode_white_list_flag = ngx.ctx.rate_vcode_white_list_flag, rate_vcode_black_list_flag = ngx.ctx.rate_vcode_black_list_flag}
                                -- ngx.exec("/baishancloud-juhe-api/adapter", ngx.encode_args(args))
                            end
                            if ngx.var.arg_caller_info and ngx.var.arg_caller_info == 'yes' then
                                ngx.say(cjson.encode(caller))
                                ngx.exit(ngx.HTTP_OK)
                            end
                            if ngx.var.arg_get_env ~= nil then
                                ngx.say(os.getenv(ngx.var.arg_get_env))
                                ngx.exit(ngx.HTTP_OK)
                            end
                            --acl policy
                            local acl_policy_key = project['project_id'] .. "_" .. caller['caller_id']
                            if tonumber(caller['caller_id']) == 0 then
                                acl_policy_key = project['project_id'] .. "_" .. caller['caller_id'] .. "_" .. remote_addr
                            end
                            local limit_result = {OK = 1, FORBIDDEN = 2}
                            local acl_policy = acl_policy:new(acl_policy_key, caller)
                            if acl_policy ~= nil then
                                if acl_policy:ip_black_limit() == limit_result["FORBIDDEN"] then
                                    exit_code.err_exit("RemoteAddrInBlackList")
                                end
                                if acl_policy:ip_white_limit() == limit_result["FORBIDDEN"] then
                                    exit_code.err_exit("RemoteAddrNotInWhiteList")
                                end
                                if acl_policy:right_limit() == limit_result["FORBIDDEN"] then
                                    exit_code.err_exit("CallerMethodError")
                                end
                                if acl_policy:rate_limit() == limit_result["FORBIDDEN"] then
                                    exit_code.err_exit("CallerOverRateLimit")
                                end
                            end

                            local args = {request_uri = request_uri, api_id = project['project_id'], api_adapter_version = project['project_version'], rate = ngx.ctx.rate, rate_limit_redis_key = ngx.ctx.rate_limit_redis_key}
                            ngx.exec("/baishancloud-juhe-api/adapter", ngx.encode_args(args))

                            -- ngx.print(ngx.var.remote_addr .. "\n")
                            -- ngx.exit(ngx.HTTP_OK)
                            -- ngx.print(method .. " " .. full_path .. "caller: " .. caller .. "\n")
                            -- ngx.exit(ngx.HTTP_OK)
                        end)
                    end
                end
            end
        end
    end
    -- r:match(router_match)
    -- ngx.exit(ngx.HTTP_OK)
    -- ngx.say(cjson.encode(porjcet_info))
    -- porjcet_info = cjson.decode(porjcet_info)
    -- if porjcet_info == nil or #porjcet_info == 0 then
    --     exit_code.err_exit("PathInfoNotFound")
    -- end

    local ok, errmsg = r:execute(
        ngx.var.request_method,
        ngx.var.uri,
        ngx.req.get_uri_args(),  -- all these parameters
        ngx.req.get_post_args(), -- will be merged in order
        {other_arg = 1})         -- into a single "params" table

    if not ok then
        -- ngx.status = 200
        exit_code.err_exit("PathInfoNotFound")
        -- ngx.status = 404
        -- ngx.print("Not found!")
        -- ngx.log(ngx.ERROR, errmsg)
        -- ngx.exit(ngx.HTTP_OK)
    end
end

function main()
    local backend_path
    local table_policy_id_config
    local valid_request_path
    local api_id
    local api_path_name
    local api_path_status
    local api_path_id
    local mode
    local backend_mode
    local backends
    local proxy_timeout
    local table_swagger
    local api_adapter_version

    local api_config_shm = api_config_shm:new(request_host)
    local path_info = api_config_shm:get_path_info()
    path_info = cjson.decode(path_info)
    if path_info == nil or #path_info == 0 then
        exit_code.err_exit("PathInfoNotFound")
    end

    api_path_name, api_id, api_path_id, mode, backend_mode, api_path_status, valid_request_path = util.get_api_path_id(path_info, original_uri, request_uri)
    if api_path_id == nil then
        exit_code.err_exit("ApiPathNotFound")
    end
    if api_id == nil then
       exit_code.err_exit("ApiNotFound")
    end
    ngx.var.api_path_id = api_path_id
    ngx.var.api_id = api_id

    if api_path_status ~= "on" then
        exit_code.err_exit("ApiPathStatusOff")
    end

    -- determine whethter the request is the api adapter test
    if api_id > 1000000 then
        api_adapter_version = api_config_shm:get_adapter_version(api_id)
        local api_adapter_test_ip = config.get_conf("api_adapter_test_ip")
        local api_adapter_test_header = req_headers["X-Prism-Debug-Enable"]
        if remote_addr == api_adapter_test_ip and api_adapter_test_header == "true" then
            ngx.var.caller_id = 0
            ngx.log(ngx.ERR, remote_addr .. " " .. api_adapter_test_ip .. " " .. api_adapter_test_header)
            local args = {request_uri = request_uri, api_id = api_id, api_adapter_version = api_adapter_version, rate = nil, rate_limit_redis_key = nil, rate_vcode_white_list_flag = nil, rate_vcode_black_list_flag = nil}
            ngx.exec("/baishancloud-juhe-api/adapter", ngx.encode_args(args))
        end
    end

    --ua limit
    local security_config = api_config_shm:get_security_config(api_id)
    local security_config_table = cjson.decode(security_config)
    if security_config_table ~= nil and next(security_config_table) ~= nil and security_config_table["status"] == "true" then
        local ua_lower
        local ua = req_headers["user-agent"]
        local ua_risk = security_config_table["user_agent"]
        if ua ~= nil and #ua > 0 then
            ua_lower = string.lower(ua)
	    else
            ua_lower = ""
        end
        for _,v in pairs(ua_risk) do
            local ua_risk_lower = string.lower(v["name"])
            local m, err = ngx.re.match(ua_lower, ua_risk_lower)
            if m then
                exit_code.err_exit("UserAgentInBlackList")
	        else
                if err then
	   	             ngx.log(ngx.ERR, "user-agent match error: " .. err)
                end
            end
        end
    end

    -- api adapter's api_id > 1000000
    --[[
    if api_id < 1000000 then
        local swagger_config = api_config_shm:get_swagger_config(api_path_id)
        table_swagger = cjson.decode(swagger_config)
        if table_swagger == nil or table_swagger["paths"] == nil or table_swagger["paths"][api_path_name] == nil or table_swagger["paths"][api_path_name]["proxy"] == nil or table_swagger["paths"][api_path_name]["auth"] == nil then
            exit_code.err_exit("ApiPathSwaggerParseError")
        end

        --body limit
        local content_length = req_headers['content-length']
        local max_body_size_bytes = table_swagger["paths"][api_path_name]["proxy"]["max_body_size_bytes"]
        if content_length ~= nil and tonumber(content_length) > tonumber(max_body_size_bytes) then
            ngx.exit(413)
        end

        --check method
        local allow_methods = table_swagger["paths"][api_path_name]["methods"]
        if util.check_method(allow_methods) == nil then
            exit_code.err_exit("ApiPathMethodError")
        end
    end

    ]]

    --auth
    local caller_id = auth.auth_request(api_config_shm, api_path_id)
    if caller_id == nil then
        if api_id < 1000000 then
            local anon = table_swagger["paths"][api_path_name]["auth"]["anonymous"]
            if anon == true or anon == "true" then
                table_policy_id_config = table_swagger["paths"][api_path_name]["auth"]["anonymous_acl_policy"]
                caller_id = 0
                ngx.var.caller_id = 0
            else
                exit_code.err_exit("AuthFail")
            end
        elseif api_id > 1000000 then
            local anon_config = api_config_shm:get_adapter_anon_acl_policy(api_path_id)
            local table_anon_config = cjson.decode(anon_config)
            local anon = table_anon_config["adapter_path_status"]
            if anon == "on" then
                table_policy_id_config = table_anon_config
                caller_id = 0
                ngx.var.caller_id = 0
            else
                exit_code.err_exit("AuthFail")
            end
        end
    else
        ngx.var.caller_id = caller_id
        local policy_id_config = api_config_shm:get_policy_config(caller_id)
        table_policy_id_config = cjson.decode(policy_id_config)
    end

    --acl policy
    local acl_policy_key = api_path_id .. "_" .. caller_id
    if tonumber(caller_id) == 0 then
        acl_policy_key = api_path_id .. "_" .. caller_id .. "_" .. remote_addr
    end

    local rate_black_white_list = api_config_shm:get_rate_black_white_list(api_path_id)
    local rate_black_white_list_table = cjson.decode(rate_black_white_list)
    local rate_black_key_shm = acl_policy_key .. "_rate_black"
    local res_shm_black = api_config_shm:get_rate_shm_key(rate_black_key_shm)
    if res_shm_black ~= nil then
        ngx.ctx.rate_vcode_black_list_flag = true
        exit_code.err_exit("RemoteAddrInVcodeBlackList")
    end
    if security_config_table["status"] == "true" and security_config_table["vcode_status"] == "true" then
        for _,v in pairs(rate_black_white_list_table) do
            if v["ip"] == remote_addr and tonumber(v["caller_id"]) == tonumber(caller_id) and v["type"] == "black" and ngx.localtime() < v["expired_time"] then
                ngx.ctx.rate_vcode_black_list_flag = true
                exit_code.err_exit("RemoteAddrInVcodeBlackList")
            end
        end
    end

    local rate_key_shm = acl_policy_key .. "_rate_white"
    local res_shm_white = api_config_shm:get_rate_shm_key(rate_key_shm)
    if res_shm_white then
        ngx.ctx.rate_vcode_white_list_flag = true
    end

    if rate_black_white_list_table ~= nil and ngx.ctx.rate_vcode_white_list_flag ~= true then
        for _,v in pairs(rate_black_white_list_table) do
            if v["ip"] == remote_addr and tonumber(v["caller_id"]) == tonumber(caller_id) and v["type"] == "white" and ngx.localtime() < v["expired_time"] then
                ngx.ctx.rate_vcode_white_list_flag = true
                break
            end
        end
    end

    local limit_result = {OK = 1, FORBIDDEN = 2}
    local acl_policy = acl_policy:new(acl_policy_key, table_policy_id_config)
    if acl_policy ~= nil then
        local ok = acl_policy:ip_black_limit()
        if ok == limit_result["FORBIDDEN"] then
            exit_code.err_exit("RemoteAddrInBlackList")
        end

        local ok = acl_policy:ip_white_limit()
        if ok == limit_result["FORBIDDEN"] then
            exit_code.err_exit("RemoteAddrNotInWhiteList")
        end

        local ok = acl_policy:right_limit()
        if ok == limit_result["FORBIDDEN"] then
            exit_code.err_exit("CallerMethodError")
        end

        local ok = acl_policy:referer_limit()
        if ok == limit_result["FORBIDDEN"] then
            exit_code.err_exit("RefererNotInWhiteList")
        end

        if ngx.ctx.rate_vcode_white_list_flag ~= true and ngx.ctx.rate_vcode_black_list_flag ~= true then
            ok = acl_policy:rate_limit()
        else
            ok = limit_result["OK"]
        end
        if ok == limit_result["FORBIDDEN"] then
            if security_config_table["status"] ~= "true" or security_config_table["vcode_status"] ~= "true" then
                exit_code.err_exit("CallerOverRateLimit")
            end

            local rate_key = acl_policy_key .. "_rate"
            local rate_hash_key = acl_policy_key

            if ngx.ctx.rate_vcode_white_list_flag ~= true then
                local acl_redis = config.get_conf("acl_redis")
                local red = util.rate_redis_init(acl_redis, rate_hash_key)
                if red then
                    local res1, err1 = red:exists(rate_key)
                    if not res1 then
                        ngx.log(ngx.ERR, "failed to exists: " .. err1)
                        return
                    end
                    local res2, err2 = red:incr(rate_key)
                    if not res2 then
                        ngx.log(ngx.ERR, "failed to incr: " .. err2)
                        return
                    end
                    if tonumber(res1) == 0 then
                        local res3, err3 = red:expire(rate_key, 60)
                        if not res3 then
                            ngx.say(ngx.ERR, "failed to incr: " .. err3)
                            return
                        end
                    end

                    local vcode_max_incorrect_number = security_config_table["vcode_max_incorrect_number"]
                    if res2 > vcode_max_incorrect_number then
                        local rate_white_black_url = config.get_conf("rate_white_black_url")
                        local vcode_black_expired_s = security_config_table["vcode_black_expired_s"]
                        if vcode_black_expired_s > 0 and vcode_black_expired_s <= 3 then
                            api_config_shm:set_rate_shm_key(rate_black_key_shm, vcode_black_expired_s)
                        elseif vcode_black_expired_s > 3 then
                            api_config_shm:set_rate_shm_key(rate_black_key_shm, 3)
                        end

                        local body_data_table = { type = "black", ip = remote_addr, expired_time = ngx.time() + vcode_black_expired_s, api_path_id = api_path_id, caller_id = caller_id }
                        local body_data_json = cjson.encode(body_data_table)
                        util.send_http(rate_white_black_url, "POST", body_data_json, { ["Content-Type"] = "application/json" })

                        util.delete_all_rate_keys(red, rate_hash_key)
                        ngx.ctx.rate_vcode_black_list_flag = true
                        exit_code.err_exit("RemoteAddrInVcodeBlackList")
                    end

                    local ok, err = red:set_keepalive(10000, 500)
                    if not ok then
                        ngx.log("failed to set keepalive: ", err)
                    end

                    local html = config.get_conf("rate_vcode_html")
                    local timeout = config.get_conf("sign_timeout")
                    local captcha_create_url = util.get_sign_url("GET", "/baishancloud-juhe-captcha/create", timeout)
                    local captcha_check_url = util.get_sign_url("POST", "/baishancloud-juhe-captcha/check", timeout)
                    local html = string.format(html, captcha_check_url, captcha_create_url, captcha_create_url)
                    local cookie_table = {}
                    table.insert(cookie_table, string.format("caller=%s; path=/baishancloud-juhe-captcha",util.encrypt(caller_id)))
                    table.insert(cookie_table, string.format("apipath=%s; path=/baishancloud-juhe-captcha",util.encrypt(api_path_id)))
                    ngx.header.content_type="text/html"
                    ngx.header['Set-Cookie'] = cookie_table
                    ngx.say(html)
                    ngx.exit(200)
                end
            end
        end
    end

    if api_id > 1000000 then
        local args = {request_uri = request_uri, api_id = api_id, api_adapter_version = api_adapter_version, rate = ngx.ctx.rate, rate_limit_redis_key = ngx.ctx.rate_limit_redis_key, rate_vcode_white_list_flag = ngx.ctx.rate_vcode_white_list_flag, rate_vcode_black_list_flag = ngx.ctx.rate_vcode_black_list_flag}
        ngx.exec("/baishancloud-juhe-api/adapter", ngx.encode_args(args))
    end

    -- upstream get peer
    local get_peer_key = "get_peer_" .. api_path_id
    if backend_mode == "tunnel" then
        backends = table_swagger["paths"][api_path_name]["proxy"]["tunnel_backends"]
    else
        backends = table_swagger["paths"][api_path_name]["proxy"]["backends"]
    end
    if backends == nil or #backends == 0 then
        exit_code.err_exit("BackendNotFound")
    end

    local peers = api_config_shm.get(get_peer_key)
    local table_peers = cjson.decode(peers)
    if table_peers == nil then
        api_config_shm.set(get_peer_key, cjson.encode(backends), 86400)
        table_peers = backends
    end
    ----check if the backend is updated
    if #backends ~= #table_peers then
        api_config_shm.set(get_peer_key, cjson.encode(backends), 86400)
        table_peers = backends
    else
        for k,v in pairs(backends) do
            if backends[k]["url"] ~= table_peers[k]["url"] or backends[k]["weight"] ~= table_peers[k]["weight"] then
                api_config_shm.set(get_peer_key, cjson.encode(backends), 86400)
                table_peers = backends
                break
            end
        end
    end

    for k,v in pairs(backends) do
        if table_peers[k]["current_weight"] == nil then
            table_peers[k]["current_weight"] = backends[k]["weight"]
        end
    end

    local backend_num = util.upstream_get_peer(table_peers, get_peer_key, api_config_shm)
    local backend_url = table_peers[backend_num]["url"]
    local backend_parse = util.url_parse(backend_url)
    table_peers[backend_num]["current_weight"] = table_peers[backend_num]["current_weight"] - 1
    api_config_shm.set(get_peer_key, cjson.encode(table_peers), 86400)
    ----backend_urls = [selected_backend_url, backup_backend_url...]
    ----when redispatch use backup backend url.
    local backend_urls = {backend_url}
    for i=1, #table_peers do
        if i ~= backend_num then
            table.insert(backend_urls, table_peers[i]["url"])
        end
    end

    ngx.ctx.ip_list = {}
    for _,backend_url in pairs(backend_urls) do
        local backend_ip
        local tmp_backend_parse = util.url_parse(backend_url)
        local tmp_backend_host = tmp_backend_parse["host"]
        local check_ip_result = util.check_ip(tmp_backend_host)
        if check_ip_result == nil then
            local ip_list = util.resolver_query(tmp_backend_host)
            if ip_list ~= nil and #ip_list > 0 then
                if config.get_conf("backend_filter_status") == "on" and backend_mode ~= "tunnel" then
                    if config.get_conf("backend_filter_white_list") ~= nil then
                        if config.get_conf("backend_filter_white_list")[tmp_backend_host] == nil then
                            for _,ip in pairs(ip_list) do
                                if util.check_private_ip(ip) ~= nil then
                                    exit_code.err_exit("BackendIsPrivateIp")
                                end
                            end
                        end
                    end
                end

                local idx = math.random(1, #ip_list)
                backend_ip = ip_list[idx]
            end
        else
            if config.get_conf("backend_filter_status") == "on" and backend_mode ~= "tunnel" then
                local check_private_ip_result = util.check_private_ip(tmp_backend_host)
                if check_private_ip_result ~= nil then
                    local a = config.get_conf("backend_filter_white_list")
                    if config.get_conf("backend_filter_white_list") ~= nil then
                        if config.get_conf("backend_filter_white_list")[tmp_backend_host] == nil then
                            exit_code.err_exit("BackendIsPrivateIp")
                        end
                    end
                end
            end

            backend_ip = tmp_backend_host
        end

        if backend_ip ~= nil then
            table.insert(ngx.ctx.ip_list, {backend_ip = backend_ip, backend_port = tmp_backend_parse["port"], backend_host = tmp_backend_host})
        else
            exit_code.err_exit("BackendResolverError")
        end
    end

    --proxy
    ngx.var.backend_host = table_swagger["paths"][api_path_name]["proxy"]["backend_host"]
    if #ngx.var.backend_host == 0 then
        ngx.var.backend_host = backend_parse["host"]
    end
    if table_swagger["paths"][api_path_name]["proxy"][mode] == nil or table_swagger["paths"][api_path_name]["proxy"][mode]["timeout_s"] == nil then
        proxy_timeout = 60
    else
        proxy_timeout = table_swagger["paths"][api_path_name]["proxy"][mode]["timeout_s"]
    end
    if valid_request_path == nil then
        valid_request_path = ""
    elseif string.len(backend_parse["path"]) == 0 and util.startswith(valid_request_path, "/") then
        valid_request_path = string.sub(valid_request_path, 2)
    end

    if not util.startswith(backend_parse["path"], "/") then
        backend_path = "/" .. backend_parse["path"]
    else
        backend_path = backend_parse["path"]
    end

    -- mode
    -- local request_token = api_path_id .. "-" .. uuid()
    --[[
    if mode ~= "default" then
        local backend = backend_parse["scheme"] .. "://" .. ngx.ctx.ip_list[1]["backend_ip"] .. ":" .. ngx.ctx.ip_list[1]["backend_port"]  .. backend_path .. valid_request_path

        if mode == "sync" then
            local nginx_num = config.get_conf("nginx_num")
            if nginx_num == nil then
                nginx_num = 4
            end
            local max_concurrent = table_swagger["paths"][api_path_name]["proxy"][mode]["max_concurrency"]
            if max_concurrent == nil then
                max_concurrent = 100
            end
            local concurrent_threshold = max_concurrent/nginx_num
            local intelligent_swith = ngx.shared.intelligent_switch
            intelligent_swith:add(api_path_id, 0, 1)
            local ok,err = intelligent_swith:incr(api_path_id, 1)
            if tonumber(ok) > tonumber(concurrent_threshold) then
                sync_handle(api_path_id, backend, proxy_timeout, request_token)
            else
                ngx.var.proxy_url = backend_parse["scheme"] .. "://yunlian" .. backend_path .. valid_request_path
            end
        elseif mode == "async" then
            async_handle(api_path_id, backend)
        elseif mode == "websocket" then
            local function wb_cleanup()
                ws_buffer:delete(request_token)
                exit_code.err_exit("WebSocketClientAbort")
            end

            local ok, err = ngx.on_abort(wb_cleanup)
            if ok == nil then
                exit_code.err_exit("WebSocketRegisterAbortFail", "failed to register the on_abort callback: " .. err)
            end

            local server = require "resty.websocket.server"
            local wb, err = server:new{
                timeout = 5000,  -- in milliseconds
                max_payload_len = 65535,
            }
            if wb == nil then
                exit_code.err_exit("WebSocketNewFail", "failed to new websocket: " .. err)
            end

            ngx.thread.spawn(websocket_receive, wb, api_path_id, request_token, backend)
            ngx.thread.spawn(websocket_send, wb, request_token)
        end
    else
        ]]
        --default mode
        local filter_status
        ngx.var.proxy_url = backend_parse["scheme"] .. "://yunlian" .. backend_path .. valid_request_path
        if table_swagger["paths"][api_path_name]["filter"] ~= nil then
            filter_status = table_swagger["paths"][api_path_name]["filter"]["status"]
        end
        if filter_status == true then

            -- filter
            local filter_backend_url = backend_parse["scheme"] .. "://" .. ngx.var.backend_host  .. backend_path .. valid_request_path
            local body_data = {url = filter_backend_url, api_path_id = api_path_id}
            local body_data_json = cjson.encode(body_data)
            local filter_url = config.get_conf("filter_url")
            local filter_res = util.send_http(filter_url, "PUT", body_data_json, { ["Content-Type"] = "application/json" })
            if filter_res == nil or filter_res.status == nil then
                exit_code.err_exit("FilterTimeout")
            end
            if util.startswith(filter_res.status, "20") then
                for k, v in pairs(filter_res.headers) do
                    ngx.header[k] = v
                end
                ngx.say(filter_res.body)
            end
            ngx.exit(filter_res.status)

        else

            --cache
            local nginx_cache_key = api_id .. original_uri
            local cache_config = table_swagger["paths"][api_path_name]["proxy"]["cache"]

            if cache_config ~= nil and (cache_config["cache_status"] == true or cache_config["cache_status"] == "true") then
                if cache_config["cache_expires_time_ms"] > 0 then
                    local headers = req_headers
                    local sorted_headers = util.pairsbykey(headers)
                    if cache_config["header_cache_status"] == true or cache_config["header_cache_status"] == "true" then
                        for _,v in pairs(sorted_headers) do
                            nginx_cache_key = nginx_cache_key .. v
                        end
                    else
                        if #cache_config["header_cache_field"] > 0 then
                            for _,v in pairs(cache_config["header_cache_field"]) do
                                local header_value = sorted_headers[v]
                                if header_value ~= nil then
                                    nginx_cache_key = nginx_cache_key .. header_value
                                end
                            end
                        end
                    end

                    local uri_args = ngx.req.get_uri_args()
                    if next(uri_args) ~= nil then
                        local sorted_uri_args = util.pairsbykey(uri_args)
                        if cache_config["query_string_cache_status"] == true or cache_config["query_string_cache_status"] == "true" then
                            for _,v in pairs(sorted_uri_args) do
                                if v ~= nil then
                                    nginx_cache_key = nginx_cache_key .. v
                                end
                            end
                        else
                            if #cache_config["query_string_cache_field"] > 0 then
                                for _,v in pairs(cache_config["query_string_cache_field"]) do
                                    local query_value = sorted_uri_args[v]
                                    if query_value ~= nil then
                                        nginx_cache_key = nginx_cache_key .. query_value
                                    end
                                end
                            end
                        end
                    end

                    local url2cachekey = ngx.shared.url2cachekey
                    local cache_key = ngx.md5(nginx_cache_key)
                    local cache_key_shm = url2cachekey:get(cache_key)
                    if cache_key_shm == nil then
                        cache_key_shm = request_token
                        local cache_expires_time_s = cache_config["cache_expires_time_ms"]/1000
                        local ok, err = url2cachekey:add(cache_key, cache_key_shm, cache_expires_time_s)
                    end

                    if cache_key_shm ~= nil then
                        local args = {proxy_url = ngx.var.proxy_url, ip_list = cjson.encode(ngx.ctx.ip_list), backend_host = ngx.var.backend_host, api_id = api_id, api_path_id = api_path_id, caller_id = ngx.var.caller_id, rate = ngx.ctx.rate, rate_limit_redis_key = ngx.ctx.rate_limit_redis_key, original_uri = original_uri, nginx_cache_key = nginx_cache_key, rate_vcode_white_list_flag = ngx.ctx.rate_vcode_white_list_flag, rate_vcode_black_list_flag = ngx.ctx.rate_vcode_black_list_flag}
                        ngx.exec("/" .. cache_key_shm .. "/baishancloud?" .. ngx.encode_args(args))
                    end

                end
            end
        end
    -- end


end

main2()
