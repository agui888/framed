local api_config_shm = require "lib.api_config_shm"
local ssl = require "ngx.ssl"
local server_name = ssl.server_name()
ssl.clear_certs()
function get_local_file(file)
    local f = assert(io.open(file))
    if not f then
        ngx.log(ngx.ERR, "no such file ", file)
        return
    end
    local file_data = f:read("*a")
    f:close()
    return file_data
end

function set_ssl_crt_and_key(cert_data, pkey_data)
    cert_data, err = ssl.cert_pem_to_der(cert_data)
    if not cert_data then
        ngx.log(ngx.ERR, "failed to convert pem cert to der cert: ", err)
        return
    end

    local ok, err = ssl.set_der_cert(cert_data)
    if not ok then
        ngx.log(ngx.ERR, "failed to set DER cert: ", err)
        return
    end

    pkey_data, err = ssl.priv_key_pem_to_der(pkey_data)
    if not pkey_data then
        ngx.log(ngx.ERR, "failed to convert pem key to der key: ", err)
        return
    end
    local ok, err = ssl.set_der_priv_key(pkey_data)
    if not ok then
        ngx.log(ngx.ERR, "failed to set private key: ", err)
        return
    end

    return true
end

local cert_data
local pkey_data
if not server_name then
    ngx.log(ngx.ERR, "got invalid server_name, send default cert instead")
    server_name = "bsclink.com"
end
if string.match(server_name, ".*%.bsclink%.com$") then
    server_name = "bsclink.com"
end

if server_name == "bsclink.com" then
    local ssl_root = "/usr/local/bsc/openresty/nginx/conf/"
    local ssl_crt = ssl_root .. server_name .. ".crt"
    local ssl_key = ssl_root .. server_name .. ".key"
    cert_data = get_local_file(ssl_crt)
    if not cert_data then
        ngx.log(ngx.ERR, "get local crt file failed")
        return
    end

    pkey_data = get_local_file(ssl_key)
    if not pkey_data then
        ngx.log(ngx.ERR, "get local key file failed")
        return
    end
else
    local api_config_shm = api_config_shm:new(server_name)
    local host_ssl_info = api_config_shm:get_ssl_info()
    local table_host_ssl_info = cjson.decode(host_ssl_info)
    cert_data = table_host_ssl_info["ssl_crt"]
    pkey_data = table_host_ssl_info["ssl_crt_key"]
end

local ok = set_ssl_crt_and_key(cert_data, pkey_data)
if not ok then
    ngx.log(ngx.ERR, "failed to set SNI cert")
end
