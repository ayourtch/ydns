local ydns = require("ydns")
local socket = require("socket")

host = host or "127.0.0.1"
port = port or 53
class = 1 or class
name = "ietf.org" or name

if arg then
  host = arg[1] or host
  class = arg[2] or class
  name = arg[3] or name
end

udp = assert(socket.udp())
assert(udp:setpeername(host, port))
print("Using remote host '" ..host.. "' and port " .. port .. "...")
req = ydns.encode_request(name, class, 0x1234)
udp:send(req)
dgram = assert(udp:receive())
ret = ydns.decode_reply(dgram)

for k,v in pairs(ret) do
  if type(v) == "table" then
    print(k, "======>")
    for k1,v1 in pairs(v) do
      print(":", k1, v1) 
    end
  else
    print(k,v) 
  end
end
