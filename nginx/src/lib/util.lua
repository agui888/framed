local _M = {};
local modelName = "util";
_G[modelName] = _M;

local config = require "lib.config"

function _M.check_method(allow_methods)
    local request_method = ngx.req.get_method()
    for k,v in pairs(allow_methods) do
        if string.upper(request_method) == string.upper(v) then
            return true
    end
    end

    return nil
end

function _M.url_parse(url)
    local result = {}
    local i,j = string.find(url, "^https?://[%w-.:]*%.[%w-.:]*")
    result['path'] = string.sub(url, j+1)
    local url = string.sub(url, i, j)

    local i1,j1 = string.find(url, "%a+")
    result['scheme'] = string.sub(url, i1, j1)

    local i2,j2 = string.find(url, "[%w-.]*%.[%w-.]*")
    result['host'] = string.sub(url, i2, j2)

    local i3,j3 = string.find(url, ".*[%w-.]*%.[%w-.]*:")
    if i3 then
        result['port'] = string.sub(url, j3+1)
    elseif result.scheme == "https" then
        result['port'] = 443
    else
        result['port'] = 80
    end

    return result
end


function _M.check_ip(ip)
    if type(ip) == "string" then
        local i,j = ngx.re.find(ip, "^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$", "jo")
        if i ~= nil then
            local ipaddr =string.sub(ip, i, j)
            return ipaddr
        end
    end

    return
end


function _M.check_private_ip(ip)
    if ip == nil then
        return
    end

    if _M.startswith(ip, "10.") or _M.startswith(ip, "192.168.") or ip == "127.0.0.1" then
        return ip
    end
    for num=16,31 do
        local ip_prefix = "172." .. num .. "."
        if _M.startswith(ip, ip_prefix) then
            return ip
        end
    end

    return
end


function _M.get_api_id(path_2_apipathid)
    local api_id
    if path_2_apipathid ~= nil and #path_2_apipathid > 0 then
        if path_2_apipathid[1] ~= nil then
            api_id = path_2_apipathid[1]["apiid"]
        end
    end

    return api_id
end


function _M.get_api_path_id(path_2_apipathid, original_uri, request_uri)
    local path
    local api_path_id
    local api_id
    local valid_request_uri
    local mode
    local backend_mode
    local matched_max_len_pcre = 0
    local matched_max_len_str = 0
    local path_info_pcre
    local path_info_str
    local path_info

    if path_2_apipathid ~= nil and path_2_apipathid[1] ~= nil and path_2_apipathid[1]["apiid"] > 1000000 then

        for k, v in pairs(path_2_apipathid) do
            local encode_pathname = ngx.escape_uri(v.pathname)
            local path_pattern, n, err = ngx.re.gsub(encode_pathname, "%7B[a-zA-Z0-9-_%]+%7D", "([a-zA-Z0-9-_%]+|)", "i")
            if path_pattern and n > 0 then
                path_pattern = path_pattern .. "$"
                local encode_original_uri = ngx.escape_uri(original_uri)
                local m, err = ngx.re.match(encode_original_uri, path_pattern)
                if m then
                   path_info = v
                   break
                else
                   if err then
                        ngx.log(ngx.ERR, "api adapter error: ", err)
                   end
                end
            else
                if original_uri == v.pathname then
                    path_info = v
                    break
                end
            end
        end

    else

        for k, v in pairs(path_2_apipathid) do
            if v.pcre_status == "on" then
                local from, to, err = ngx.re.find(request_uri, v.pathname, "jo")
                if from then
                    local matched_len_pcre = tonumber(to) - tonumber(from) + 1
                    if matched_len_pcre > matched_max_len_pcre then
                        path_info_pcre = v
                        matched_max_len_pcre = matched_len_pcre
                    end
                end
            else
                if _M.startswith(request_uri, v.pathname) then
                    local matched_len_str = string.len(v.pathname)
                    if matched_len_str > matched_max_len_str then
                        path_info_str = v
                        matched_max_len_str = matched_len_str
                    end
                end
            end
        end

        if matched_max_len_pcre > 0 then
            path_info = path_info_pcre
            valid_request_uri = request_uri
        else
            path_info = path_info_str
            if string.len(request_uri) >= matched_max_len_str then
                valid_request_uri = string.sub(request_uri, matched_max_len_str+1)
            end
        end
    end

    if path_info ~= nil then
        matched_path = path_info.pathname
        api_id = path_info.apiid
        api_path_id = path_info.pathid
        mode = path_info.mode
        backend_mode = path_info.backend_mode
        status = path_info.status
    end

    return matched_path, api_id, api_path_id, mode, backend_mode, status, valid_request_uri
end


function _M.resolver_query(domain)
    local json = ngx.shared.resolver_cache:get(domain)
    if json then
        local cache_data = cjson.decode(json)
        if cache_data then
            --ngx.say("from cache")
            return cache_data
        end
    end

    local ip_list = {}
    local resolver = require "resty.dns.resolver"
    local r, err = resolver:new{
        nameservers = { "223.5.5.5", {"223.6.6.6", 53} },
        retrans = 5,  -- 5 retransmissions on receive timeout
        timeout = 2000,  -- 2 sec
    }

    if not r then
        ngx.log(ngx.ERR, "failed to instantiate the resolver: ", err)
        return
    end

    local answers, err = r:query(domain)
    if not answers then
        ngx.log(ngx.ERR, "failed to query the DNS server: ", err)
        return
    end

    if answers.errcode then
        ngx.log(ngx.ERR, "server returned error code: ", answers.errcode,
                ": ", answers.errstr)
        return
    end

    for i, ans in ipairs(answers) do
        --[[ngx.say(ans.name, " ", ans.address or ans.cname,
                            " type:", ans.type, " class:", ans.class,
                            " ttl:", ans.ttl)
        ]]
        table.insert(ip_list, ans.address)
    end

    ngx.shared.resolver_cache:set(domain, cjson.encode(ip_list), 300)
    return ip_list
end

function _M.send_http(uri, request_method, request_body, request_header)
    if not request_header then
        request_header = { ["Content-Type"] = "application/x-www-form-urlencoded" }
    end
    local http = require "http"
    local httpc = http.new()
    httpc:set_timeout(10000)
    local res, err = httpc:request_uri(uri, {
      method = request_method,
      body = request_body,
      headers = request_header
    })

    if not res then
        ngx.log(ngx.ERR, "failed to request: ", err, ", uri:", uri)
        return
    end

    return res
end


function _M.get_request_body()
    ngx.req.read_body()
    local data = ngx.req.get_body_data()
    if not data then
        local file_name = ngx.req.get_body_file()
        if file_name then
            local f = assert(io.open(file_name, 'r'))
            data = f:read("*all")
            f:close()
        end
    end

    return data
end


function _M.startswith(s, pref)
    return string.sub(s, 1, string.len(pref)) == pref
end

function _M.endswith(s, suff)
    return string.sub(s, -1, string.len(suff)) == suff
end

-- function _M.endswith(s, e)
--     return string.sub(s, string.len(s)-string.len(e)+1) == e
-- end


function _M.upstream_get_peer(peers, get_peer_key, api_config_shm)
    local n = 0
    local reset = 0
    while true do
        for i=1, #peers do
            repeat
                if peers[i]["current_weight"] <= 0 then
                    break
                end
            n = i
            while i < #peers do
                i = i + 1
                repeat
                    if peers[i]["current_weight"] <= 0 then
                        break
                    end
                if peers[n]["current_weight"] * 1000 / peers[i]["current_weight"] > peers[n]["weight"] * 1000 / peers[i]["weight"] then
                    return n
                end
                n = i
                until true
            end
            if (peers[i]["current_weight"] > 0) then
                n = i
            end
            return n
            until true
        end

        if reset > 0 then
            return 1
        end
        reset = reset + 1

        for i=1, #peers do
            peers[i]["current_weight"] = peers[i]["weight"]
        end
        api_config_shm.set(get_peer_key, cjson.encode(peers), 86400)
    end
end


function _M.encrypt(data)
    local aes = require "resty.aes"
    local str = require "resty.string"
    local aes_128_cbc_md5 = aes:new("baishan-juhe-lee")
    local encrypted = ngx.encode_base64(aes_128_cbc_md5:encrypt(tostring(data)))
    return encrypted
end


function _M.decrypt(data)
    local aes = require "resty.aes"
    local str = require "resty.string"
    local aes_128_cbc_md5 = aes:new("baishan-juhe-lee")
    return aes_128_cbc_md5:decrypt(ngx.decode_base64(data))
end


function _M.rate_redis_init(acl_redis, rate_key)
    local acl_redis_len = #acl_redis
    local get_redis_num = ngx.crc32_short(rate_key) % acl_redis_len
    get_redis_num = get_redis_num + 1

    local redis = require "resty.redis"
    local red = redis:new()
    red:set_timeout(5000) -- 1 sec

    local ok, err = red:connect(acl_redis[get_redis_num]["ip"], acl_redis[get_redis_num]['port'])
    if not ok then
        for i=1, acl_redis_len do
            if i ~= get_redis_num then
                ok, err = red:connect(acl_redis[i]["ip"], acl_redis[i]['port'])
                if ok then
                    break
                end
            end
        end

        if not ok then
            ngx.log(ngx.ERR, "failed to connect redis: " .. err)
            return
        end
    else
        return red
    end

end


function _M.get_sign_url(method, uri, timeout)
    local key = config.get_conf("sign_key")
    local expires = tonumber(ngx.time()) + tonumber(timeout)
    local url = ngx.var.http_host .. uri
    local hmac_body = method .. expires .. url
    local digest = ngx.hmac_sha1(key, hmac_body)
    local sign = ngx.md5(digest)
    local result = uri .. "?sign=" .. sign .. "&expires=" .. expires
    return result
end


function _M.check_sign_url(uri)
    local expires = ngx.req.get_uri_args()["expires"]
    local arg_sign = ngx.req.get_uri_args()["sign"]
    if expires == nil or arg_sign == nil then
        return
    end

    local time = ngx.time()
    if tonumber(expires) < tonumber(time) then
        return
    end

    local url = ngx.var.http_host .. uri
    local key = config.get_conf("sign_key")
    local method = ngx.req.get_method()
    local hmac_body = method .. expires .. url
    local digest = ngx.hmac_sha1(key, hmac_body)
    local sign = ngx.md5(digest)
    if sign ~= arg_sign then
        return
    end

    return true
end


function _M.pairsbykey(t)
    local sort_t = {}
    local result = {}
    for k in pairs(t) do
        table.insert(sort_t, k)
    end
    table.sort(sort_t)

    for _,v in pairs(sort_t) do
        result[v] = t[v]
    end
    return result
end


function _M.delete_all_rate_keys(red, rate_hash_key)
    red:del(rate_hash_key .. "_minute", rate_hash_key .. "_minute_block", rate_hash_key .. "_rate", rate_hash_key .. "_hour", rate_hash_key .. "_hour_block", rate_hash_key .. "_day", rate_hash_key .. "_day_block")
    local rate_limit_shm = ngx.shared.rate_limit
    local ok = rate_limit_shm:delete(rate_hash_key .. "_minute_block")
    local ok = rate_limit_shm:delete(rate_hash_key .. "_hour_block")
    local ok = rate_limit_shm:delete(rate_hash_key .. "_day_block")
end


return _M;
