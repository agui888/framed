local _M = {};
local mt = { __index = _M }
local modelName = "websocket_req";
_G[modelName] = _M;

local yunlian = ngx.shared.yunlian
local util = require "lib.util"
local config = require "lib.config"


function _M.new(self)
    return setmetatable({host = host}, mt)
end


function _M.websocket_receive(wb)
    wb:set_timeout(1000)  -- change the network timeout to 1 second
    while true do
        local data, typ, err = wb:recv_frame()
        if not data then
            ngx.log(ngx.ERR, "failed to receive a frame: ", err)
        end
        if typ == "close" then
            local bytes, err = wb:send_close(1000, "enough, enough!")
            if not bytes then
                ngx.log(ngx.ERR, "failed to send the close frame: ", err)
                return
            end
            local code = err
            ngx.log(ngx.ERR, "closing with status code ", code, " and message ", data)
            return
        end

        if typ == "ping" then
            local bytes, err = wb:send_pong(data)
            if not bytes then
                ngx.log(ngx.ERR, "failed to send frame: ", err)
                return
            end
        elseif typ == "pong" then

        elseif data then 
            ngx.log(ngx.ERR, "received a frame of type ", typ, " and payload ", data)
        end
        ngx.sleep(2)
    end
end


function _M.websocket_send(wb) 
    wb:set_timeout(500)  -- change the network timeout to 0.5 second
    while true do
        local bytes, err = wb:send_text(ngx.localtime())
        if not bytes then
            ngx.log(ngx.ERR, "failed to send a text frame: ", err)
        end
        ngx.sleep(2)
    end
end

          local server = require "resty.websocket.server"
          local wb, err = server:new{
              timeout = 5000,  -- in milliseconds
              max_payload_len = 65535,
          }
          if not wb then
              ngx.log(ngx.ERR, "failed to new websocket: ", err)
              return ngx.exit(444)
          end
          ngx.thread.spawn(websocket_receive, wb)        
          ngx.thread.spawn(websocket_send, wb)        

          local function my_cleanup()
               ngx.log(ngx.ERR, 'client already disconnected')
               ngx.exit(444)
          end
          
          local ok, err = ngx.on_abort(my_cleanup)
          if not ok then
              ngx.log(ngx.ERR, "failed to register the on_abort callback: ", err)
              ngx.exit(500)
          end
