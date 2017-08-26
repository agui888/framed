cjson = require "cjson.safe"
function return_data(code, msg, data)
    if msg == nil then
        msg = ""
    end
    if data == nil then
        data = "[]"
    else
        data = cjson.encode(data)
    end
    local str = string.format('{"code": %s, "message": "%s", "data": %s}', code, msg, data)
    return str
end

