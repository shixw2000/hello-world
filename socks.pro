#proxy protocol
This protocol records in [rfc1928](https://www.ietf.org/rfc/rfc1928.txt).

##auth
###auth.req
> |ver|len_meth|methods|
|:-:|:-:|:-:|
|1|1|1-255|
|0x5|2|0x00,0x02|

ver: 
    * 0x5: socks5, 
    * 0x4: socks4
methods: 
    * 0x0: no need to auth
    * 0x1: gssapi
    * 0x2: username/password
    * 0x3~0x7f: iana reserv
    * 0x80~0xfe: customer reserv
    * 0xff: no acceptable method
###auth.rsp
> |ver|method|
|:-:|:-:|
|1|1|
|0x5|0x2|

###user_pass.req
> |ver|ulen|user|plen|passwd|
|:-:|:-:|:-:|:-:|:-:|
|1|1|1-255|1|1-255|
|0x1|5|shixw|6|123456|

###user_pass.rsp
> |ver|status|
|:-:|:-:|
|1|1|
|0x1|0|

##cmd
###cmd.req
> |ver|cmd|rsv|atype|addr|port|
|:-:|:-:|:-:|:-:|:-:|:-:|
|1|1|1|1|var|2|
|0x5|0x1|0x0|0x1|0xC0A80001|0x50|

cmd:
    * 0x1: connect
    * 0x2: bind
    * 0x3: udp
atype:
    * 0x1: ipv4
    * 0x3: domain
    * 0x4: ipv6
addr:
    * ipv4: 4 Bytes
    * ipv6: 16B
    * domain: |1|1-255|
###cmd.rsp
> |ver|rsp|rsv|atype|addr|port|
|:-:|:-:|:-:|:-:|:-:|:-:|
|1|1|1|1|var|2|

##data
###udp.data
> |rsv|frag|atype|addr|port|data|
|:-:|:-:|:-:|:-:|:-:|:-:|
|2|1|1|var|2|...|

