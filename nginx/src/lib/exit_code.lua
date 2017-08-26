local _M = {};
local modelName = "exit_code";
_G[modelName] = _M;

local _error_to_http_code = {

    InvalidRequest = ngx.HTTP_BAD_REQUEST,
    PathInfoNotFound = ngx.HTTP_NOT_FOUND,
    ApiNotFound = ngx.HTTP_NOT_FOUND,
    ApiPathNotFound = ngx.HTTP_NOT_FOUND,
    ApiPathStatusOff = ngx.HTTP_FORBIDDEN,
    ApiPathSwaggerParseError = ngx.HTTP_NOT_FOUND,
    ApiPathMethodError = ngx.HTTP_NOT_ALLOWED,
    UserAgentInBlackList = ngx.HTTP_FORBIDDEN,
    RefererNotInWhiteList = ngx.HTTP_FORBIDDEN,
    AuthFail = ngx.HTTP_UNAUTHORIZED,
    SignAuthFail = ngx.HTTP_UNAUTHORIZED,
    RemoteAddrInBlackList = ngx.HTTP_FORBIDDEN,
    RemoteAddrNotInWhiteList = ngx.HTTP_FORBIDDEN,
    CallerMethodError = ngx.HTTP_NOT_ALLOWED,
    CallerOverRateLimit = ngx.HTTP_TOO_MANY_REQUESTS,
    RemoteAddrInVcodeBlackList = ngx.HTTP_FORBIDDEN,
    BackendNotFound = ngx.HTTP_BAD_GATEWAY,
    BackendIsPrivateIp = ngx.HTTP_BAD_GATEWAY,
    BackendResolverError = ngx.HTTP_BAD_GATEWAY,
    HalfAsyncResponseCodeError = ngx.HTTP_GATEWAY_TIMEOUT,
    HalfAsyncResponseTimeout = ngx.HTTP_GATEWAY_TIMEOUT,
    WebSocketNewFail = ngx.HTTP_CLOSE,
    WebSocketClientAbort = 499,
    WebSocketRegisterAbortFail = ngx.HTTP_CLOSE,
    WebSocketReceiveError = ngx.HTTP_CLOSE,
    WebSocketPassiveCloseFail = ngx.HTTP_CLOSE,
    WebSocketSendFail = ngx.HTTP_CLOSE,
    WebSocketActiveClose = ngx.HTTP_CLOSE,
    FilterTimeout = ngx.HTTP_GATEWAY_TIMEOUT

}

local _error_to_message = {

    AuthFail = {code_message = "401 Authorization Required", code_reasen = "401001:auth failed"},
    SignAuthFail = {code_message = "401 Authorization Required", code_reasen = "401002: sign auth failed"},
    ApiPathStatusOff = {code_message = "403 Forbidden", code_reasen = "403001:api path status is off"},
    RemoteAddrInBlackList = {code_message = "403 Forbidden", code_reasen = "403002:remote addr in black list"},
    RemoteAddrNotInWhiteList = {code_message = "403 Forbidden", code_reasen = "403003:remote addr not in white list"},
    UserAgentInBlackList = {code_message = "403 Forbidden", code_reasen = "403004:user agent in black list"},
    RefererNotInWhiteList = {code_message = "403 Forbidden", code_reasen = "403005:referer not in white list"},
    RemoteAddrInVcodeBlackList = {code_message = "403 Forbidden", code_reasen = "403006:remote addr in vcode black list"},
    CallerOverRateLimit = {code_message = "429 Too Many Requests", code_reasen = "403004:request over rate limit"},
    PathInfoNotFound = {code_message = "404 Not Found", code_reasen = "404001:host does not have any path and apipathid info"},
    ApiNotFound = {code_message = "404 Not Found", code_reasen = "404002:request dose not match any api"},
    ApiPathNotFound = {code_message = "404 Not Found", code_reasen = "404003:request dose not match any api path"},
    ApiPathSwaggerParseError = {code_message = "404 Not Found", code_reasen = "404004:parse api path swagger config failed"},
    ApiPathMethodError = {code_message = "405 Not Allowed", code_reasen = "405001:request method is not allowed, please check the api path config"},
    CallerMethodError = {code_message = "405 Not Allowed", code_reasen = "405002:request method is not allowed, please check the caller config"},
    BackendNotFound = {code_message = "502 bad geteway", code_reasen = "502001:not configured backend machine"},
    BackendIsPrivateIp = {code_message = "502 bad geteway", code_reasen = "502002:backend ip is a private ip"},
    BackendResolverError = {code_message = "502 bad geteway", code_reasen = "502003:backend domain resolver failed"},
    HalfAsyncResponseCodeError = {code_message = "504 Gateway Time-out", code_reasen = "504001:taskqueue response error"},
    HalfAsyncResponseTimeout = {code_message = "504 Gateway Time-out", code_reasen = "504002:taskqueue response timeout"},
    FilterTimeout = {code_message = "504 Gateway Time-out", code_reasen = "504003:filter server response timeout"}

}

function _M.err_exit(code, log_msg)
    if not code then
    	code = 'InvalidRequest'
    end
    ngx.status = _error_to_http_code[code] or ngx.HTTP_BAD_REQUEST
    local message = _error_to_message[code]
    if message ~= nil then
        ngx.header["Content-Type"] = "text/html"
        local res_html = string.format('<html><head><title>%s</title></head><body bgcolor="white"><center><h1>%s</h1></center><hr><center>%s</center></body></html>', message["code_message"], message["code_message"], message["code_reasen"])
        ngx.header["x-error-code"] = code
        ngx.say(res_html)
        ngx.eof()
        ngx.log(ngx.ERR, message["code_reasen"])
    end
    if log_msg ~= nil then
        ngx.log(ngx.ERR, log_msg)
    end

    ngx.exit(ngx.HTTP_OK)
end


return _M
