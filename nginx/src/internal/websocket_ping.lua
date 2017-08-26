local util = require "lib.util"
local ws_buffer = ngx.shared.websocket_buffer
local result_tokens = {}
local request_tokens_num = ngx.req.get_headers()["request-tokensnum"]
local request_tokens_num =  tonumber(request_tokens_num)
if request_tokens_num == nil then
    ngx.say(return_data(1, "header request-tokensnum dose not exist"))
    ngx.exit(200)
end
if request_tokens_num >= 1 and request_tokens_num <= 4 then
    for i=1, request_tokens_num do
        local header_name = "request-tokens" .. i
        local request_tokens = ngx.req.get_headers()[header_name]
        local table_request_tokens = cjson.decode(request_tokens)

        if table_request_tokens ~= nil then
            for _,request_token in pairs(table_request_tokens) do
                local tmp = {}
                local ok = ws_buffer:get(request_token)
                if ok then
                    tmp["status"] = true
                else
                    tmp["status"] = false
                end
                tmp["request_token"] = request_token
                table.insert(result_tokens, tmp)
            end
        else
            ngx.say(return_data(1, "header " .. header_name .. " filed is not json format"))
            ngx.exit(200)
        end
    end
    ngx.say(return_data(0, "success", result_tokens))
else
    ngx.say(return_data(1, "header " .. request-tokensnum .. " filed should be greater than or equal to 1 and less than or equal to 4"))
end
