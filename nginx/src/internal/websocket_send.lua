local util = require "lib.util"
local ws_buffer = ngx.shared.websocket_buffer 

function sempost(table_request_tokens, body_data, request_url)
    local disconnect_link = 0
    for _,request_token in pairs(table_request_tokens) do
        local ok = ws_buffer:get(request_token)
        if ok then
            local ok, err = ws_buffer:set(request_url, body_data, 120)
            if not ok then
                ngx.log(ngx.ERR, "key:" .. request_url .. ", websocket update shm failed: " .. err)
            end
        else
            disconnect_link = disconnect_link + 1
        end

        local flag_key = request_token .. "_flag"
        local ok, err = ws_buffer:set(flag_key, "new", 120)
    end

    for i=1, 10 do
        local request_token_count = ws_buffer:get(request_url .. "_request_token_count")
        local request_token_incr = ws_buffer:get(request_url .. "_request_token_incr")
        if request_token_incr + disconnect_link >= request_token_count then
            break
        else
            ngx.sleep(0.1) 
        end
    end
end


-- read normal body
--function read_body(request_url, table_request_tokens)
--    local sock, err = ngx.req.socket()
--    if not sock then
--        ngx.log(ngx.ERR, "failed to new: ", err)
--        return
--    end

--    while true do
--        local data, err, partial = sock:receive()
--        if data == nil then
--            if partial == nil then
--                ngx.log(ngx.ERR, "failed to receive: ", err)
--                break
--            end
--            data = partial
--            if string.len(data) > 0 then
--                sempost(table_request_tokens, data, request_url)
--                break
--            end
--        else
--            sempost(table_request_tokens, data, request_url)
--        end
--    end
--end

-- read chunked body
function read_chunked_body(request_url, table_request_tokens)
    local sock, err = ngx.req.socket(true)
    if not sock then
        ngx.log(ngx.ERR, "failed to new: ", err)
        return
    end

    while true do
        local line, err = sock:receive()
        if not line then
            ngx.log(ngx.ERR, "failed to receive chunk size: ", err)
        end

        local size = tonumber(line, 16)
        if not size then
            ngx.log(ngx.ERR, "bad chunk size: ", line)
        end

        if size == 0 then -- last chunk
            -- receive the last line
            line, err = sock:receive()
            if not line then
                ngx.log(ngx.ERR, "failed to receive last chunk: ", err)
            end

            if line ~= "" then
                ngx.log(ngx.ERR, "bad last chunk: ", line)
            end

            eof = true
            break
        end

        local chunk, err = sock:receive(size)
        if not chunk then
            ngx.log(ngx.ERR, "failed to receive chunk of size ", size, ": ", err)
        end

        local data, err = sock:receive(2)
        if not data then
            ngx.log(ngx.ERR, "failed to receive chunk terminator: ", err)
        end

        if data ~= "\r\n" then
            ngx.log(ngx.ERR, "bad chunk terminator: ", data)
        end

        if chunk then
            sempost(table_request_tokens, chunk, request_url)
        end

    end

    local ok, err = sock:send("HTTP/1.1 200 OK\r\nConnection: close\r\nContent-Length: "
                    .. 2 .. "\r\n\r\n" .. "ok")
    if not ok then
        ngx.log(ngx.ERR, "failed to send response: ", err)
    end
end


local request_tokens_num = ngx.req.get_headers()["request-tokensnum"]
local request_tokens_num =  tonumber(request_tokens_num)
if request_tokens_num == nil then
    ngx.say(return_data(1, "header request-tokensnum dose not exist")) 
    ngx.exit(200)
end

if request_tokens_num >= 1 and request_tokens_num <= 4 then
    for i=1, request_tokens_num do
        local request_url
        local header_name = "request-tokens" .. i
        local request_tokens = ngx.req.get_headers()[header_name]
        local table_request_tokens = cjson.decode(request_tokens)
        if table_request_tokens ~= nil then
            for i=1, #table_request_tokens do
                local valid_request_token = table_request_tokens[i]
                local ok = ws_buffer:get(valid_request_token)
                if ok ~= nil then
                    request_url = ok 
                end
            end
            if request_url == nil then
                ngx.exit(200)
            end
            local table_request_tokens_len = #table_request_tokens
            ws_buffer:set(request_url .. "_request_token_count", table_request_tokens_len, 120)
            ws_buffer:set(request_url .. "_request_token_incr", 0, 120)

            read_chunked_body(request_url, table_request_tokens) 
        else
            ngx.say(return_data(1, "header " .. header_name .. " filed is not json format"))
            ngx.exit(200)
        end
    end
    ngx.say(return_data(0, "success"))
else
    ngx.say(return_data(1, "header " .. request-tokensnum .. " filed should be greater than or equal to 1 and less than or equal to 4"))
end
