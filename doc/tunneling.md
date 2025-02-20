
# Bidirectional tunnel

1. There is `**/tunnel:create` method returning `tunid` as `String`
1. Upon successful tunnel creation, the `**/tunnel/<tunid>` node exists
1. The tunnel data exchange is started by first `**/tunnel/<tunid>:write` call with `seqNo` set to 0. Response to this call is received,
   when some data on other tunnel side is ready to read. `**/tunnel/<tunid>::write` will never time-out.
1. Data is read from tunnel as responses to first `**/tunnel/<tunid>:write`. All responses are sent with `request-id` of first `write` call,
   but with increasing `SeqNo` attribute value. `SeqNo` starts at 0, it can wrap around but it will never be negative.
1. Data is written to tunel as further `**/tunnel/<tunid>:write` requests. All requests are sent with `request-id` of first `write` call, but with increasing `SeqNo`.
   Note, that write request and response are not paired, since the `request-id` is always the same. More than that, number of
   `write` requests and responses is not the same.
1. Tunnel is closed when:
   1. `**/tunnel/<tunid>:close` is called
   1. RpcError message is sent by one of side
   1. There is no traffic for 1 minute
1. Tunnel creation and destruction is signalized by `**/tunnel/<tunid>:ls:lsmod` signal
